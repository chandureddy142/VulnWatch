import os
from flask import Blueprint, current_app, jsonify, render_template, request, send_file, session
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

    Access control: ownership check only — no API key required.
    Guests can view reports for their own scans (matched via guest_device_id cookie).
    """
    db = get_session()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404

    if not _check_report_access(scan):
        return (
            jsonify(
                {
                    "error": "Access Denied",
                    "message": "You do not have permission to view this report.",
                }
            ),
            403,
        )

    diff_data = _build_diff_map(scan)
    finding_snippets = {
        f.id: get_remediation_snippets(f.category, f.title) for f in scan.findings
    }
    return render_template(
        "results.html",
        scan=scan,
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


@reports_bp.route("/<int:scan_id>/html", methods=["GET"])
def download_html_report(scan_id: int):
    """Serve standalone static HTML report file.

    Access control: ownership check only — guests can download their own reports.
    """
    db = get_session()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404

    if not _check_report_access(scan):
        return (
            jsonify(
                {
                    "error": "Access Denied",
                    "message": "You do not have permission to download this report.",
                }
            ),
            403,
        )

    reports_dir = _get_reports_dir()
    html_path = os.path.join(reports_dir, f"scan_{scan.id}.html")

    if not os.path.exists(html_path):
        generate_html_report(scan, html_path)

    return send_file(html_path, mimetype="text/html")


@reports_bp.route("/<int:scan_id>/json", methods=["GET"])
def download_json_report(scan_id: int):
    """Download scan findings as a JSON artifact.

    Access control: ownership check only — guests can download their own reports.
    """
    db = get_session()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404

    if not _check_report_access(scan):
        return (
            jsonify(
                {
                    "error": "Access Denied",
                    "message": "You do not have permission to download this report.",
                }
            ),
            403,
        )

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


@reports_bp.route("/<int:scan_id>/pdf", methods=["GET"])
def download_pdf_report(scan_id: int):
    """Download executive PDF assessment report.

    Access control: ownership check only — guests can download their own reports.
    """
    db = get_session()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan Not Found", "scan_id": scan_id}), 404

    if not _check_report_access(scan):
        return (
            jsonify(
                {
                    "error": "Access Denied",
                    "message": "You do not have permission to download this report.",
                }
            ),
            403,
        )

    reports_dir = _get_reports_dir()
    pdf_path = os.path.join(reports_dir, f"scan_{scan.id}.pdf")

    if not os.path.exists(pdf_path):
        generate_pdf_report(scan, pdf_path)

    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"webguard_executive_report_{scan.id}.pdf",
    )
