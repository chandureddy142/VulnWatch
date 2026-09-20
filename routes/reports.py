import hashlib
import os
import re
from urllib.parse import urlparse
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from sqlalchemy.orm import joinedload
from database.db import get_session
from database.models import Finding, Scan, ScanStatus, TriageStatus
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.pdf_report import generate_pdf_report
from scanner.remediation_snippets import get_remediation_snippets
from services.auth import require_api_key

from utils.privacy import check_scan_ownership

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


def _get_reports_dir():
    reports_dir = current_app.config.get("REPORTS_DIR")
    if not reports_dir:
        reports_dir = os.path.join(current_app.root_path, "reports_output")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def _check_report_access(scan) -> bool:
    """Return True if the current request session/cookie owns this scan.

    Ownership rules (guest-friendly):
    1. Authenticated Google user: ``session['user_id'] == scan.user_id``
    2. Guest with persistent cookie: ``request.cookies['guest_device_id'] == scan.guest_session_id``
    3. Guest with session key (legacy): ``session['guest_id'] == scan.guest_session_id``
    4. Scan has no owner (no user_id and no guest_session_id) → allow (backwards compat)
    """
    # Scan has no recorded owner → accessible to everyone (legacy / admin scans)
    if not scan.user_id and not scan.guest_session_id:
        return True

    user_id = session.get("user_id")
    # Authenticated user
    if user_id is not None:
        if scan.user_id and scan.user_id == user_id:
            return True
        # Authenticated users cannot see other users' scans
        return False

    # Guest: check persistent cookie first, then session fallback
    guest_device_id = (
        request.cookies.get("guest_device_id", "").strip()
        or session.get("guest_id", "")
        or session.get("guest_session_id", "")
    )
    if scan.guest_session_id and guest_device_id:
        return scan.guest_session_id == guest_device_id

    return False


def _build_diff_map(current_scan: Scan) -> dict:
    """
    Compare current scan findings against the previous scan of the same target URL.

    Returns a dict mapping finding title → diff status ('NEW', 'PERSISTENT')
    and a list of resolved finding titles from the previous scan.
    """
    db = get_session()
    query = db.query(Scan).filter(
        Scan.target_url == current_scan.target_url,
        Scan.id != current_scan.id,
        Scan.status == ScanStatus.COMPLETED,
    )
    if current_scan.user_id:
        query = query.filter(Scan.user_id == current_scan.user_id)
    elif current_scan.guest_session_id:
        query = query.filter(Scan.guest_session_id == current_scan.guest_session_id)

    prev_scan = query.order_by(Scan.started_at.desc()).first()

    if not prev_scan:
        return {
            "has_previous": False,
            "finding_diff": {},
            "resolved_titles": [],
            "previous_scan_id": None,
        }

    prev_titles = {f.title for f in prev_scan.findings}
    current_titles = {f.title for f in current_scan.findings}

    finding_diff = {}
    for finding in current_scan.findings:
        if finding.title in prev_titles:
            finding_diff[finding.id] = "PERSISTENT"
        else:
            finding_diff[finding.id] = "NEW"

    resolved_titles = list(prev_titles - current_titles)

    return {
        "has_previous": True,
        "finding_diff": finding_diff,
        "resolved_titles": resolved_titles,
        "previous_scan_id": prev_scan.id,
    }


@reports_bp.route("/<int:scan_id>", methods=["GET"])
def view_report(scan_id: int):
    """Render interactive results view for a scan.

    Access control:
    Step 1: If anonymous (neither Google user nor active guest), redirect to login preserving destination in `next`.
    Step 2: If authenticated/guest, verify ownership. Rejection flashes permission warning and returns 403 redirect to dashboard.
    """
    is_logged_in = bool(session.get("user_id"))
    is_guest = bool(session.get("is_guest") or request.cookies.get("guest_device_id"))
    if not is_logged_in and not is_guest:
        return redirect(url_for("auth.login", next=request.url, reason="login_required"))

    db = get_session()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404

    if not _check_report_access(scan):
        flash("You do not have permission to view this confidential audit report.", "danger")
        return redirect(url_for("dashboard.index"))

    diff_data = _build_diff_map(scan)
    finding_snippets = {
        f.id: get_remediation_snippets(f.category, f.title) for f in scan.findings
    }
    return render_template(
        "results.html",
        scan=scan,
        subdomains=scan.subdomains,
        probed_subdomains=scan.probed_subdomains,
        diff_data=diff_data,
        finding_snippets=finding_snippets,
    )


@reports_bp.route("/<int:scan_id>/findings/<int:finding_id>/triage", methods=["PATCH"])
@require_api_key
def update_finding_triage(scan_id: int, finding_id: int):
    """Update the triage status and notes for a specific finding."""
    db = get_session()
    finding = db.query(Finding).filter_by(id=finding_id, scan_id=scan_id).first()
    if not finding:
        return jsonify({"error": "Finding Not Found"}), 404

    if not _check_report_access(finding.scan):
        return (
            jsonify(
                {
                    "error": "Access Denied",
                    "message": "You do not have permission to triage findings for this scan.",
                }
            ),
            403,
        )

    data = request.get_json() or {}

    triage_status_str = data.get("triage_status", "").strip()
    triage_notes = data.get("triage_notes", "").strip()

    # Validate triage status
    valid_statuses = {ts.value for ts in TriageStatus}
    if triage_status_str and triage_status_str not in valid_statuses:
        return jsonify({
            "error": "Invalid triage status",
            "allowed": list(valid_statuses),
        }), 400

    if triage_status_str:
        finding.triage_status = TriageStatus(triage_status_str)
    finding.triage_notes = triage_notes or finding.triage_notes

    db.commit()
    return jsonify({"message": "Triage updated.", "finding": finding.to_dict()})


@reports_bp.route("/<int:scan_id>/export/html", methods=["GET"])
@reports_bp.route("/<int:scan_id>/html", methods=["GET"])
def download_html_report(scan_id: int):
    """Serve standalone static HTML report file with verification hash."""
    db = get_session()
    scan = db.query(Scan).options(joinedload(Scan.findings)).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404

    if not _check_report_access(scan):
        return jsonify({"error": "Access Denied", "message": "Permission denied."}), 403

    raw_str = f"{scan.target_url}_{scan.started_at}_{scan.critical_count}"
    verify_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    return render_template("export_report.html", scan=scan, hash=verify_hash)


@reports_bp.route("/<int:scan_id>/json", methods=["GET"])
def download_json_report(scan_id: int):
    """Download scan findings as a JSON artifact."""
    db = get_session()
    scan = db.query(Scan).options(joinedload(Scan.findings)).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404

    if not _check_report_access(scan):
        return jsonify({"error": "Access Denied", "message": "Permission denied."}), 403

    reports_dir = _get_reports_dir()
    json_path = os.path.join(reports_dir, f"scan_{scan.id}.json")

    if not os.path.exists(json_path):
        generate_json_report(scan, json_path)

    return send_file(
        json_path,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"webguard_scan_{scan.id}.json",
    )


@reports_bp.route("/<int:scan_id>/export/pdf", methods=["GET"])
@reports_bp.route("/<int:scan_id>/pdf", methods=["GET"])
def download_pdf_report(scan_id: int):
    """Download executive PDF report or fallback to print view."""
    db = get_session()
    scan = db.query(Scan).options(joinedload(Scan.findings)).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404

    if not _check_report_access(scan):
        return jsonify({"error": "Access Denied", "message": "Permission denied."}), 403

    reports_dir = _get_reports_dir()
    pdf_path = os.path.join(reports_dir, f"scan_{scan.id}.pdf")

    if not os.path.exists(pdf_path):
        try:
            generate_pdf_report(scan, pdf_path)
        except Exception:
            # Fallback to interactive print-ready HTML view if binary PDF engine is uninstalled
            raw_str = f"{scan.target_url}_{scan.started_at}_{scan.critical_count}"
            verify_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
            return render_template("export_report.html", scan=scan, hash=verify_hash)

    if os.path.exists(pdf_path):
        clean_host = urlparse(scan.target_url).netloc or f"scan_{scan.id}"
        clean_host = re.sub(r"[^\w\.-]", "_", clean_host)
        filename = f"VulnWatch_Audit_{scan.id}.pdf"
        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )

    raw_str = f"{scan.target_url}_{scan.started_at}_{scan.critical_count}"
    verify_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
    return render_template("export_report.html", scan=scan, hash=verify_hash)

