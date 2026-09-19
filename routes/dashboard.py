from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse
from flask import Blueprint, jsonify, render_template, request, redirect, session, url_for
from sqlalchemy import func
from database.db import get_session
from database.models import Finding, Scan, ScanStatus, SeverityLevel
from scanner.engine import cleanup_stale_scans
from services.auth import require_api_key
from utils.privacy import mask_domain, check_scan_ownership

dashboard_bp = Blueprint("dashboard", __name__)



def _compute_posture_score(critical: int, high: int, medium: int, low: int) -> int:
    """Weighted security posture score (0–100) for a single scan.

    Penalties per finding (lower is worse):
      Critical: -25, High: -15, Medium: -5, Low: -1
    Clamped to [0, 100].
    """
    raw = 100 - (25 * critical + 15 * high + 5 * medium + 1 * low)
    return max(0, min(100, raw))


def _score_tier(score: int) -> str:
    """Map a numeric posture score to a human-readable risk tier label."""
    if score >= 80:
        return "Optimal"
    elif score >= 60:
        return "Moderate Risk"
    return "Needs Attention"


@dashboard_bp.route("/", methods=["GET"])
@dashboard_bp.route("/dashboard", methods=["GET"])
def index():
    """Render dashboard summary metrics, asset inventory, and recent scans list."""
    db = get_session()
    cleanup_stale_scans(db, max_age_seconds=120)

    user_id = session.get("user_id")
    # Resolve guest identity: persistent cookie takes priority over session key
    guest_id = (
        request.cookies.get("guest_device_id", "").strip()
        or session.get("guest_id", "")
        or session.get("guest_session_id", "")
    )
    is_anonymous = not user_id and not guest_id

    # ── Tier isolation ───────────────────────────────────────────────────────
    # Tier 3 (Google auth): own scans only, fully unmasked
    # Tier 2 (guest):       own scans only, fully unmasked
    # Tier 1 (anonymous):   recent public history, ALL domains strictly masked
    if user_id:
        base_query = db.query(Scan).filter(Scan.user_id == user_id)
        viewer_owns_all = True  # always owner for their own query
    elif guest_id:
        base_query = db.query(Scan).filter(Scan.guest_session_id == guest_id)
        viewer_owns_all = True
    else:
        # Tier 1: anonymous visitor (no user_id or guest_id) has no owned scans
        base_query = db.query(Scan).filter(False)
        viewer_owns_all = False

    total_scans = base_query.count()

    # Aggregate severity totals across tenant's scans
    totals = {
        "critical": base_query.with_entities(func.sum(Scan.critical_count)).scalar() or 0,
        "high": base_query.with_entities(func.sum(Scan.high_count)).scalar() or 0,
        "medium": base_query.with_entities(func.sum(Scan.medium_count)).scalar() or 0,
        "low": base_query.with_entities(func.sum(Scan.low_count)).scalar() or 0,
        "info": base_query.with_entities(func.sum(Scan.info_count)).scalar() or 0,
    }

    # Security Posture Score — average per-scan score across COMPLETED scans for this tenant
    completed_scans = (
        base_query.filter(Scan.status == ScanStatus.COMPLETED).all()
    )
    if completed_scans:
        individual_scores = [
            _compute_posture_score(
                s.critical_count, s.high_count, s.medium_count, s.low_count
            )
            for s in completed_scans
        ]
        posture_score = round(sum(individual_scores) / len(individual_scores))
    else:
        posture_score = 100  # No audits yet — default to clean slate
    posture_tier = _score_tier(posture_score)

    # Calculate global platform volume stats for anonymous public landing view
    global_total_audits = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count()
    global_total_findings = db.query(Finding).count()
    global_completed_scans = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).all()
    if global_completed_scans:
        global_scores = [
            _compute_posture_score(s.critical_count, s.high_count, s.medium_count, s.low_count)
            for s in global_completed_scans
        ]
        global_avg_posture = round(sum(global_scores) / len(global_scores))
    else:
        global_avg_posture = 95
    global_posture_tier = _score_tier(global_avg_posture)

    # Public masked history feed for Tier 1 anonymous visitors (HTML view)
    if is_anonymous:
        public_scans_models = (
            db.query(Scan)
            .filter(Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.started_at.desc())
            .limit(20)
            .all()
        )
        public_recent_scans = []
        for s in public_scans_models:
            d = s.to_dict(user_id=None, guest_session_id=None)
            d["target_url"] = mask_domain(s.target_url, False)
            d["id"] = None
            d["recurrence"] = 1
            public_recent_scans.append(d)
    else:
        public_recent_scans = []

    # 30-day daily scan volume for sparkline
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    sparkline_query = db.query(Scan) if is_anonymous else base_query
    recent_all = (
        sparkline_query.filter(Scan.started_at >= thirty_days_ago)
        .order_by(Scan.started_at.asc())
        .all()
    )

    # Build daily counts dict keyed by date string (YYYY-MM-DD)
    daily_counts: dict = {}
    for i in range(30):
        day = (datetime.utcnow() - timedelta(days=29 - i)).strftime("%Y-%m-%d")
        daily_counts[day] = 0
    for scan in recent_all:
        day_key = scan.started_at.strftime("%Y-%m-%d")
        if day_key in daily_counts:
            daily_counts[day_key] += 1

    sparkline_data = list(daily_counts.values())

    # Per-target scan frequency & Asset Inventory aggregation
    target_freq: dict = defaultdict(int)
    all_scans = base_query.all()
    asset_groups: dict = defaultdict(list)

    for s in all_scans:
        target_freq[s.target_url] += 1
        try:
            parsed = urlparse(s.target_url)
            hostname = parsed.netloc or parsed.path.split('/')[0]
        except Exception:
            hostname = s.target_url
        if hostname:
            asset_groups[hostname].append(s)

    asset_inventory = []
    for host, scans_list in asset_groups.items():
        sorted_scans = sorted(scans_list, key=lambda x: x.started_at, reverse=True)
        latest_scan = sorted_scans[0]
        latest_score = _compute_posture_score(
            latest_scan.critical_count,
            latest_scan.high_count,
            latest_scan.medium_count,
            latest_scan.low_count,
        )
        show_real = viewer_owns_all
        asset_inventory.append({
            "hostname": mask_domain(host, show_real),
            "scan_count": len(scans_list),
            "last_scanned_at": latest_scan.started_at.strftime("%Y-%m-%d %H:%M"),
            "latest_scan_id": latest_scan.id if viewer_owns_all else None,
            "latest_status_code": latest_scan.status_code or "N/A",
            "latest_posture_score": latest_score,
            "latest_posture_tier": _score_tier(latest_score),
            "critical_count": latest_scan.critical_count,
            "high_count": latest_scan.high_count,
        })
    asset_inventory.sort(key=lambda x: x["scan_count"], reverse=True)

    # Cap public feed for Tier 1 anonymous visitors
    scan_limit = 50 if viewer_owns_all else 20
    recent_scans_models = (
        base_query.order_by(Scan.started_at.desc()).limit(scan_limit).all()
    )
    recent_scans = []
    for s in recent_scans_models:
        d = s.to_dict(
            user_id=user_id if viewer_owns_all else None,
            guest_session_id=guest_id if viewer_owns_all else None,
        )
        d["recurrence"] = target_freq.get(s.target_url, 1)
        if not viewer_owns_all:
            d["id"] = None
        recent_scans.append(d)

    if (
        request.headers.get("Accept") == "application/json"
        or request.args.get("format") == "json"
    ):
        return jsonify(
            {
                "total_scans": total_scans,
                "severity_totals": totals,
                "recent_scans": recent_scans,
                "posture_score": posture_score,
                "posture_tier": posture_tier,
                "sparkline_data": sparkline_data,
                "asset_inventory": asset_inventory,
            }
        )

    return render_template(
        "dashboard.html",
        is_anonymous=is_anonymous,
        total_scans=total_scans,
        totals=totals,
        recent_scans=recent_scans if not is_anonymous else public_recent_scans,
        posture_score=posture_score,
        posture_tier=posture_tier,
        sparkline_data=sparkline_data,
        asset_inventory=asset_inventory,
        global_total_audits=global_total_audits,
        global_total_findings=global_total_findings,
        global_avg_posture=global_avg_posture,
        global_posture_tier=global_posture_tier,
    )
