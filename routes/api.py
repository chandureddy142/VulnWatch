import hmac
import secrets
from datetime import datetime
from flask import Blueprint, jsonify, render_template, request, session
from database.db import get_session
from database.models import Finding, Scan, ScanStatus, SeverityLevel, User
from services.auth import require_api_key, _provided_api_key, get_user_by_api_key, _configured_api_key
from utils.privacy import check_scan_ownership

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/docs", methods=["GET"])
def api_docs():
    """Render enterprise API documentation page."""
    return render_template("api_docs.html")


@api_bp.route("/keys/generate", methods=["POST"])
@api_bp.route("/v1/keys/generate", methods=["POST"])
def generate_key_api():
    """Generate developer API key for Google authenticated users."""
    user_id = session.get("user_id")
    if not user_id or session.get("is_guest"):
        return jsonify({"error": "Google Sign-In required"}), 403

    db = get_session()
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        user_email = (session.get("user") or {}).get("email") or f"user_{user_id}@example.com"
        user_name = (session.get("user") or {}).get("name") or "User"
        user = User(id=user_id, email=user_email, name=user_name)
        db.add(user)
        db.commit()

    new_key = f"vw_live_{secrets.token_hex(16)}"
    user.api_key = new_key
    db.commit()

    return jsonify({
        "status": "success",
        "api_key": new_key,
        "key": new_key,
        "message": "API key generated successfully."
    })


@api_bp.route("/keys/revoke", methods=["POST"])
@api_bp.route("/v1/keys/revoke", methods=["POST"])
def revoke_key_api():
    """Revoke developer API key for Google authenticated users."""
    user_id = session.get("user_id")
    if not user_id or session.get("is_guest"):
        return jsonify({"error": "Google Sign-In required"}), 403

    db = get_session()
    user = db.query(User).filter_by(id=user_id).first()
    if user:
        user.api_key = None
        db.commit()

    return jsonify({"status": "success", "message": "API key revoked successfully."})


@api_bp.route("/v1/scan", methods=["POST"])
def ci_cd_scan_endpoint():
    """Authenticated CI/CD programmatic scan endpoint.

    Requires Bearer or X-API-Key header associated with a Google-authenticated account.
    """
    from scanner.engine import ScanEngine
    from scanner.target import validate_target_url, TargetValidationError
    from routes.dashboard import _compute_posture_score

    key = _provided_api_key()
    if not key:
        return jsonify({
            "error": "401 Unauthorized",
            "message": "Valid Google-authenticated developer API key required."
        }), 401

    db = get_session()
    user = get_user_by_api_key(key)

    if not user and key:
        expected = _configured_api_key()
        if expected and hmac.compare_digest(key, expected):
            user = db.query(User).first()
            if not user:
                user = User(email="admin@example.com", name="Admin", api_key=key)
                db.add(user)
                db.commit()

    if not user:
        return jsonify({
            "error": "401 Unauthorized",
            "message": "Valid Google-authenticated developer API key required."
        }), 401

    data = request.get_json() or request.form.to_dict() or {}
    target_url = (data.get("target") or data.get("target_url") or "").strip()
    fail_below_score = int(data.get("fail_below_score", 75))

    if not target_url:
        return jsonify({"error": "Target URL is required."}), 400

    try:
        validated_target = validate_target_url(target_url, allow_localhost=True)
    except TargetValidationError as err:
        return jsonify({"error": "Invalid target URL", "details": str(err)}), 400

    engine = ScanEngine(allow_localhost=True)
    scan = engine.execute_scan(
        validated_target,
        is_authenticated_user=True
    )
    if user and hasattr(user, 'id') and user.id:
        scan.user_id = user.id
        db.commit()

    db.refresh(scan)
    score = _compute_posture_score(
        scan.critical_count, scan.high_count, scan.medium_count, scan.low_count
    )

    status_result = "PASS" if score >= fail_below_score else "FAIL"

    findings = db.query(Finding).filter_by(scan_id=scan.id).all()
    formatted_findings = []
    for f in findings:
        formatted_findings.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if f.severity else "INFO",
            "category": f.category,
            "description": f.description,
            "remediation": f.remediation,
            "affected_url": f.affected_url,
            "cwe_id": getattr(f, "cwe_id", "CWE-200"),
            "owasp_category": getattr(f, "owasp_category", "A05:2021-Security Misconfiguration"),
        })

    return jsonify({
        "status": status_result,
        "target": scan.target_url,
        "posture_score": score,
        "fail_below_score": fail_below_score,
        "scan_id": scan.id,
        "summary": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "info": scan.info_count
        },
        "findings": formatted_findings
    }), 200


@api_bp.route("/scans", methods=["GET"])
@require_api_key
def list_scans():
    """List all scans with severity summaries, supporting limit, offset, and status filter."""
    db = get_session()
    user_id = session.get("user_id")
    guest_id = session.get("guest_id") or session.get("guest_session_id")

    query = db.query(Scan)
    if user_id:
        query = query.filter(Scan.user_id == user_id)
    elif guest_id:
        query = query.filter(Scan.guest_session_id == guest_id)

    query = query.order_by(Scan.started_at.desc())

    status_filter = request.args.get("status")
    if status_filter:
        try:
            status_enum = ScanStatus[status_filter.upper()]
            query = query.filter_by(status=status_enum)
        except KeyError:
            pass

    offset = request.args.get("offset", type=int)
    limit = request.args.get("limit", type=int)

    if offset:
        query = query.offset(offset)
    if limit:
        query = query.limit(limit)

    scans = query.all()
    return jsonify([s.to_dict(user_id=user_id, guest_session_id=guest_id) for s in scans])


@api_bp.route("/scans", methods=["POST"])
@require_api_key
def trigger_scan_api():
    """Trigger a new scan via /api/scans POST endpoint."""
    from routes.scanner import trigger_scan
    return trigger_scan()


@api_bp.route("/scans/batch", methods=["POST"])
@require_api_key
def trigger_batch_scan_api():
    """Trigger a multi-target batch scan via /api/scans/batch POST endpoint."""
    from routes.scanner import trigger_batch_scan
    return trigger_batch_scan()


@api_bp.route("/scans/<int:scan_id>", methods=["GET"])
@api_bp.route("/scan/<int:scan_id>", methods=["GET"])
@require_api_key
def get_scan(scan_id: int):
    """Retrieve scan execution status, summary metrics, and recon intelligence."""
    db = get_session()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404
    if not check_scan_ownership(scan):
        return jsonify({"error": "Access Denied", "message": "You do not have permission to access this scan."}), 403
    return jsonify(scan.to_dict())


@api_bp.route("/scan/<int:scan_id>/findings", methods=["GET"])
@require_api_key
def get_scan_findings(scan_id: int):
    """Retrieve detailed findings for a scan, with optional severity filtering."""
    db = get_session()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404
    if not check_scan_ownership(scan):
        return jsonify({"error": "Access Denied", "message": "You do not have permission to access findings for this scan."}), 403

    severity_filter = request.args.get("severity")
    query = db.query(Finding).filter_by(scan_id=scan.id)

    if severity_filter:
        try:
            sev_enum = SeverityLevel[severity_filter.upper()]
            query = query.filter_by(severity=sev_enum)
        except KeyError:
            return (
                jsonify(
                    {
                        "error": "Invalid Severity Filter",
                        "allowed": [s.name for s in SeverityLevel],
                    }
                ),
                400,
            )

    findings = query.all()
    return jsonify([f.to_dict() for f in findings])


@api_bp.route("/scan/<int:scan_id>", methods=["DELETE"])
@require_api_key
def delete_scan(scan_id: int):
    """Delete a scan record and its associated findings from the database."""
    db = get_session()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404
    if not check_scan_ownership(scan):
        return jsonify({"error": "Access Denied", "message": "You do not have permission to delete this scan."}), 403

    db.delete(scan)
    db.commit()
    return jsonify({"message": f"Scan #{scan_id} deleted successfully."})
