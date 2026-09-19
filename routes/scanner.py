import os
import uuid
from flask import Blueprint, current_app, jsonify, make_response, redirect, render_template, request, session, url_for
from database.db import get_session
from database.models import Scan, ScanStatus
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.pdf_report import generate_pdf_report
from scanner.engine import ScanEngine, cleanup_stale_scans
from scanner.target import TargetValidationError, validate_target_url
from services.notifier import dispatch_webhook
from services.auth import require_api_key, require_api_key_or_browser
from routes.settings import load_settings

from utils.privacy import check_scan_ownership

scanner_bp = Blueprint("scanner", __name__)

# Lifetime of the guest device ID cookie: 1 year
_GUEST_COOKIE_MAX_AGE = 60 * 60 * 24 * 365


def _resolve_guest_id():
    """Return (guest_device_id, is_new) from the persistent cookie or Flask session.

    Priority:
    1. ``guest_device_id`` HTTP cookie  (1-year; survives session expiry)
    2. ``guest_id`` / ``guest_session_id`` Flask session key  (legacy fallback)
    3. Generate a new UUID, store it in the session so the caller can set the
       cookie on the response.

    Returns:
        tuple: (guest_id: str, is_new: bool)
    """
    # 1. Persistent cookie (most authoritative)
    cookie_id = request.cookies.get("guest_device_id", "").strip()
    if cookie_id:
        # Sync into session for legacy code paths that read session['guest_id']
        session.setdefault("guest_id", cookie_id)
        return cookie_id, False

    # 2. Existing session key (browser already has a session cookie)
    session_id = session.get("guest_id") or session.get("guest_session_id")
    if session_id:
        return session_id, True  # is_new=True so caller sets persistent cookie

    # 3. Brand new guest — generate and store in session; caller must set cookie
    new_id = str(uuid.uuid4())
    session["guest_id"] = new_id
    return new_id, True


@scanner_bp.route("/scanner", methods=["GET"])
def scanner_form():
    """Render the scan target configuration form.

    Access tiers:
      Tier 1 (anonymous): redirect to /auth/login?reason=audit_required
      Tier 2 (guest): allow, show quota status
      Tier 3 (Google): allow, show full UI
    """
    db = get_session()
    cleanup_stale_scans(db, max_age_seconds=120)
    user_id = session.get("user_id")

    # ── Tier 1 gate: anonymous visitor ──────────────────────────────────────
    # Allow if: (a) authenticated Google user, OR
    #           (b) session is_guest flag is set, OR
    #           (c) a guest_device_id cookie already exists from a prior visit
    is_google_user = bool(user_id)
    is_guest_session = bool(session.get("is_guest"))
    has_guest_cookie = bool(request.cookies.get("guest_device_id", "").strip())

    if not is_google_user and not is_guest_session and not has_guest_cookie:
        return redirect(url_for("auth.login", reason="audit_required",
                                next=url_for("scanner.scanner_form")))

    # ── Build active scan count for the progress indicator ──────────────────
    query = db.query(Scan).filter(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING]))
    if user_id:
        query = query.filter(Scan.user_id == user_id)
    else:
        guest_id, is_new = _resolve_guest_id()
        query = query.filter(Scan.guest_session_id == guest_id)

    active_count = query.count()
    response = make_response(render_template("scanner.html", active_scan_count=active_count))

    # Establish / refresh the persistent guest device cookie on every page load
    if not user_id:
        response.set_cookie(
            "guest_device_id",
            guest_id,
            max_age=_GUEST_COOKIE_MAX_AGE,
            httponly=True,
            samesite="Lax",
        )

    return response


@scanner_bp.route("/queue", methods=["GET"])
@require_api_key_or_browser
def get_active_queue():
    """Retrieve list of running or pending scans for status polling."""
    db = get_session()
    cleanup_stale_scans(db, max_age_seconds=120)
    user_id = session.get("user_id")
    guest_id = session.get("guest_id") or session.get("guest_session_id")

    query = db.query(Scan).filter(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING]))
    if user_id:
        query = query.filter(Scan.user_id == user_id)
    elif guest_id:
        query = query.filter(Scan.guest_session_id == guest_id)
    else:
        query = query.filter(False)

    active_scans = query.order_by(Scan.started_at.desc()).all()
    return jsonify([s.to_dict(user_id=user_id, guest_session_id=guest_id) for s in active_scans])



@scanner_bp.route("/scan", methods=["POST"])
@require_api_key_or_browser
def trigger_scan():
    """Trigger a new WebGuard security posture audit for a single target URL.

    Requires explicit target authorization confirmation.
    Payload (JSON or Form):
        target_url (str): URL to audit.
        authorized (bool): Explicit confirmation that user is authorized to audit target.
    """
    if request.is_json:
        data = request.get_json() or {}
    else:
        data = request.form.to_dict()

    target_url = data.get("target_url", "").strip()
    authorized_flag = data.get("authorized") or data.get("confirm_authorization")

    # Authorization Check Verification
    is_authorized = str(authorized_flag).lower() in ("true", "1", "yes", "on")
    if not is_authorized:
        return (
            jsonify(
                {
                    "error": "Authorization Requirement Unconfirmed",
                    "message": "You must explicitly confirm authorization to perform security posture auditing on the specified target URL.",
                }
            ),
            400,
        )

    allow_localhost = current_app.config.get("ALLOW_LOCALHOST", True)

    # Target URL Syntax & Scope Validation
    try:
        validated_url = validate_target_url(
            target_url, allow_localhost=allow_localhost
        )
    except TargetValidationError as e:
        return jsonify({"error": "Invalid Target URL", "message": str(e)}), 400

    # --- Guest quota enforcement & ownership tagging ---
    db = get_session()
    user_id = session.get("user_id")
    guest_cookie_is_new = False
    if user_id:
        guest_session_id = None  # authenticated user – no guest tracking needed
    else:
        guest_session_id, guest_cookie_is_new = _resolve_guest_id()
        guest_limit = current_app.config.get("GUEST_SCAN_LIMIT", 3)
        guest_count = db.query(Scan).filter_by(guest_session_id=guest_session_id).count()
        if guest_count >= guest_limit:
            if not request.is_json:
                # Browser form-POST: redirect directly to login page
                return redirect(url_for("auth.login", reason="quota"))
            return (
                jsonify(
                    {
                        "error": f"Guest limit reached ({guest_count}/{guest_limit} scans). "
                                 "Please sign in with Google to continue.",
                        "limit_reached": True,
                        "redirect": url_for("auth.login", reason="quota", _external=False),
                    }
                ),
                403,
            )

    # Instantiate Scan Engine & Execute Audit
    engine = ScanEngine(
        timeout=current_app.config.get("SCAN_TIMEOUT", 10),
        user_agent=current_app.config.get(
            "USER_AGENT", "WebGuard-Security-Posture-Auditor/1.0"
        ),
        allow_localhost=allow_localhost,
    )

    try:
        scan = engine.execute_scan(validated_url)
    except Exception:
        error_id = uuid.uuid4().hex
        current_app.logger.exception("Scan execution failed id=%s", error_id)
        return jsonify({"error": "Scan execution failed.", "error_id": error_id}), 500

    # Tag ownership on the persisted scan record
    if user_id:
        scan.user_id = user_id
    elif guest_session_id:
        scan.guest_session_id = guest_session_id
    db.commit()

    # Compute posture score for webhook payload
    posture_score = max(
        0,
        min(
            100,
            100 - (15 * scan.critical_count + 8 * scan.high_count
                   + 3 * scan.medium_count + 1 * scan.low_count),
        ),
    )

    # Dispatch webhook alert if Critical/High findings exist
    try:
        app_settings = load_settings()
        dispatch_webhook(
            scan_id=scan.id,
            target_url=scan.target_url,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            posture_score=posture_score,
            webhook_url=app_settings.get("webhook_url") or None,
        )
    except Exception:
        pass  # Notification failures must never break the scan workflow

    # Automatically generate JSON, HTML, and PDF report artifacts
    reports_dir = current_app.config.get(
        "REPORTS_DIR", os.path.join(current_app.root_path, "reports_output")
    )
    os.makedirs(reports_dir, exist_ok=True)

    json_path = os.path.join(reports_dir, f"scan_{scan.id}.json")
    html_path = os.path.join(reports_dir, f"scan_{scan.id}.html")
    pdf_path = os.path.join(reports_dir, f"scan_{scan.id}.pdf")

    generate_json_report(scan, json_path)
    generate_html_report(scan, html_path)
    generate_pdf_report(scan, pdf_path)

    # Build diff vs previous scan of same target URL
    diff_summary = _compute_diff_summary(scan)

    def _set_guest_cookie(resp):
        """Attach the persistent guest_device_id cookie to a response if needed."""
        if not user_id and guest_session_id and guest_cookie_is_new:
            resp.set_cookie(
                "guest_device_id",
                guest_session_id,
                max_age=_GUEST_COOKIE_MAX_AGE,
                httponly=True,
                samesite="Lax",
            )
        return resp

    if request.is_json:
        resp = make_response(
            jsonify(
                {
                    "message": "Scan completed successfully",
                    "scan": scan.to_dict(),
                    "posture_score": posture_score,
                    "diff_summary": diff_summary,
                    "reports": {
                        "json": f"/reports/{scan.id}/json",
                        "html": f"/reports/{scan.id}/html",
                        "pdf": f"/reports/{scan.id}/pdf",
                    },
                }
            ),
            201,
        )
        return _set_guest_cookie(resp)

    return _set_guest_cookie(redirect(url_for("reports.view_report", scan_id=scan.id)))


@scanner_bp.route("/scan/batch", methods=["POST"])
@scanner_bp.route("/scanner/batch", methods=["POST"])
@require_api_key_or_browser
def trigger_batch_scan():
    """Trigger a batch of security posture audits across multiple target URLs.

    Requires explicit target authorization confirmation.
    Payload (JSON or Form):
        targets (list or str): List of target URLs or newline-separated string.
        authorized (bool): Explicit confirmation of authorization.
    """
    if request.is_json:
        data = request.get_json() or {}
    else:
        data = request.form.to_dict()

    raw_targets_input = data.get("targets") or data.get("batch_targets") or ""
    if isinstance(raw_targets_input, str):
        target_lines = [t.strip() for t in raw_targets_input.splitlines() if t.strip()]
    elif isinstance(raw_targets_input, list):
        target_lines = [str(t).strip() for t in raw_targets_input if str(t).strip()]
    else:
        target_lines = []

    if not target_lines:
        return (
            jsonify(
                {
                    "error": "No Targets Provided",
                    "message": "Please enter at least one valid target URL for batch auditing.",
                }
            ),
            400,
        )

    authorized_flag = data.get("authorized") or data.get("confirm_authorization")
    is_authorized = str(authorized_flag).lower() in ("true", "1", "yes", "on")
    if not is_authorized:
        return (
            jsonify(
                {
                    "error": "Authorization Requirement Unconfirmed",
                    "message": "You must explicitly confirm authorization to perform security posture auditing on the specified target URLs.",
                }
            ),
            400,
        )

    allow_localhost = current_app.config.get("ALLOW_LOCALHOST", True)

    # --- Guest quota enforcement & ownership tagging (batch) ---
    db_sess = get_session()
    user_id = session.get("user_id")
    guest_cookie_is_new_batch = False
    if user_id:
        guest_session_id = None
    else:
        guest_session_id, guest_cookie_is_new_batch = _resolve_guest_id()
        guest_limit = current_app.config.get("GUEST_SCAN_LIMIT", 3)
        guest_count = db_sess.query(Scan).filter_by(guest_session_id=guest_session_id).count()
        remaining = guest_limit - guest_count
        if remaining <= 0:
            if not request.is_json:
                return redirect(url_for("auth.login", reason="quota"))
            return (
                jsonify(
                    {
                        "error": f"Guest limit reached ({guest_count}/{guest_limit} scans). "
                                 "Please sign in with Google to continue.",
                        "limit_reached": True,
                        "redirect": url_for("auth.login", reason="quota", _external=False),
                    }
                ),
                403,
            )
        # Clip the batch to remaining quota
        target_lines = target_lines[:remaining]


    engine = ScanEngine(
        timeout=current_app.config.get("SCAN_TIMEOUT", 10),
        user_agent=current_app.config.get(
            "USER_AGENT", "WebGuard-Security-Posture-Auditor/1.0"
        ),
        allow_localhost=allow_localhost,
    )

    reports_dir = current_app.config.get(
        "REPORTS_DIR", os.path.join(current_app.root_path, "reports_output")
    )
    os.makedirs(reports_dir, exist_ok=True)
    app_settings = load_settings()

    batch_results = []
    errors = []

    for raw_url in target_lines:
        try:
            validated_url = validate_target_url(
                raw_url, allow_localhost=allow_localhost
            )
        except TargetValidationError as e:
            errors.append({"target_url": raw_url, "error": str(e)})
            continue

        try:
            scan = engine.execute_scan(validated_url)

            # Tag ownership
            if user_id:
                scan.user_id = user_id
            elif guest_session_id:
                scan.guest_session_id = guest_session_id
            db_sess.commit()

            posture_score = max(
                0,
                min(
                    100,
                    100 - (15 * scan.critical_count + 8 * scan.high_count
                           + 3 * scan.medium_count + 1 * scan.low_count),
                ),
            )

            # Generate reports
            json_path = os.path.join(reports_dir, f"scan_{scan.id}.json")
            html_path = os.path.join(reports_dir, f"scan_{scan.id}.html")
            pdf_path = os.path.join(reports_dir, f"scan_{scan.id}.pdf")
            generate_json_report(scan, json_path)
            generate_html_report(scan, html_path)
            generate_pdf_report(scan, pdf_path)

            diff_summary = _compute_diff_summary(scan)

            try:
                dispatch_webhook(
                    scan_id=scan.id,
                    target_url=scan.target_url,
                    critical_count=scan.critical_count,
                    high_count=scan.high_count,
                    medium_count=scan.medium_count,
                    low_count=scan.low_count,
                    posture_score=posture_score,
                    webhook_url=app_settings.get("webhook_url") or None,
                )
            except Exception:
                pass

            batch_results.append(
                {
                    "target_url": scan.target_url,
                    "scan_id": scan.id,
                    "status": scan.status.value,
                    "findings_count": len(scan.findings),
                    "posture_score": posture_score,
                    "diff_summary": diff_summary,
                }
            )
        except Exception:
            error_id = uuid.uuid4().hex
            current_app.logger.exception("Batch scan failed id=%s", error_id)
            errors.append({"target_url": raw_url, "error": "Scan execution failed.", "error_id": error_id})

    def _set_batch_guest_cookie(resp):
        if not user_id and guest_session_id and guest_cookie_is_new_batch:
            resp.set_cookie(
                "guest_device_id",
                guest_session_id,
                max_age=_GUEST_COOKIE_MAX_AGE,
                httponly=True,
                samesite="Lax",
            )
        return resp

    if not request.is_json:
        ids_str = ",".join(str(s["scan_id"]) for s in batch_results if "scan_id" in s)
        return _set_batch_guest_cookie(redirect(url_for("scanner.view_batch_results", ids=ids_str)))

    resp = make_response(
        jsonify(
            {
                "message": f"Batch assessment complete. Executed {len(batch_results)} scan(s) successfully.",
                "results": batch_results,
                "errors": errors,
            }
        ),
        201,
    )
    return _set_batch_guest_cookie(resp)


@scanner_bp.route("/batch/results", methods=["GET"])
@scanner_bp.route("/scanner/batch/results", methods=["GET"])
@require_api_key_or_browser
def view_batch_results():
    """Render executive summary for a completed batch audit."""
    ids_param = request.args.get("ids", "").strip()
    if not ids_param:
        return redirect(url_for("scanner.scanner_form"))

    try:
        scan_ids = [int(i.strip()) for i in ids_param.split(",") if i.strip().isdigit()]
    except Exception:
        scan_ids = []

    if not scan_ids:
        return redirect(url_for("scanner.scanner_form"))

    db = get_session()
    scans_models = (
        db.query(Scan)
        .filter(Scan.id.in_(scan_ids))
        .order_by(Scan.started_at.desc())
        .all()
    )

    if not scans_models:
        return jsonify({"error": "No scans found for specified batch IDs"}), 404

    if any(not check_scan_ownership(scan) for scan in scans_models):
        return jsonify({"error": "Access Denied", "message": "You do not have permission to view batch results for these scans."}), 403

    total_targets = len(scans_models)
    scans_data = []

    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_info = 0
    total_score_sum = 0

    for scan in scans_models:
        posture_score = max(
            0,
            min(
                100,
                100 - (15 * scan.critical_count + 8 * scan.high_count
                       + 3 * scan.medium_count + 1 * scan.low_count),
            ),
        )
        total_score_sum += posture_score
        total_critical += scan.critical_count
        total_high += scan.high_count
        total_medium += scan.medium_count
        total_low += scan.low_count
        total_info += scan.info_count

        tier = "Optimal"
        if posture_score < 50:
            tier = "Critical Attention"
        elif posture_score < 70:
            tier = "Elevated Risk"
        elif posture_score < 90:
            tier = "Moderate Risk"

        scans_data.append(
            {
                "model": scan,
                "dict": scan.to_dict(),
                "posture_score": posture_score,
                "posture_tier": tier,
            }
        )

    avg_posture_score = round(total_score_sum / total_targets) if total_targets > 0 else 100
    avg_tier = "Optimal"
    if avg_posture_score < 50:
        avg_tier = "Critical Attention"
    elif avg_posture_score < 70:
        avg_tier = "Elevated Risk"
    elif avg_posture_score < 90:
        avg_tier = "Moderate Risk"

    aggregate_metrics = {
        "total_targets": total_targets,
        "avg_posture_score": avg_posture_score,
        "avg_posture_tier": avg_tier,
        "total_findings": total_critical + total_high + total_medium + total_low + total_info,
        "critical_count": total_critical,
        "high_count": total_high,
        "medium_count": total_medium,
        "low_count": total_low,
        "info_count": total_info,
    }

    if (
        request.headers.get("Accept") == "application/json"
        or request.args.get("format") == "json"
    ):
        return jsonify(
            {
                "aggregate_metrics": aggregate_metrics,
                "scans": [s["dict"] for s in scans_data],
            }
        )

    return render_template(
        "batch_results.html",
        scans_data=scans_data,
        aggregate_metrics=aggregate_metrics,
        scan_ids_str=ids_param,
    )



def _compute_diff_summary(current_scan: Scan) -> dict:
    """Compare current scan findings against the previous scan of the same target URL."""
    db = get_session()
    prev_scan = (
        db.query(Scan)
        .filter(
            Scan.target_url == current_scan.target_url,
            Scan.id != current_scan.id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.started_at.desc())
        .first()
    )

    if not prev_scan:
        return {"has_previous": False, "new": 0, "persistent": 0, "resolved": 0}

    current_titles = {f.title for f in current_scan.findings}
    prev_titles = {f.title for f in prev_scan.findings}

    new_findings = current_titles - prev_titles
    persistent_findings = current_titles & prev_titles
    resolved_findings = prev_titles - current_titles

    return {
        "has_previous": True,
        "previous_scan_id": prev_scan.id,
        "new": len(new_findings),
        "persistent": len(persistent_findings),
        "resolved": len(resolved_findings),
    }
