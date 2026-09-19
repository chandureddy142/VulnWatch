from flask import Blueprint, jsonify, render_template, request, session
from database.db import get_session
from database.models import Finding, Scan, ScanStatus, SeverityLevel
from services.auth import require_api_key
from utils.privacy import check_scan_ownership

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/docs", methods=["GET"])
def api_docs():
    """Render enterprise API documentation page."""
    return render_template("api_docs.html")


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
