from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse
from flask import Blueprint, jsonify, render_template, request, redirect, session, url_for
from sqlalchemy import func
from database.db import get_session
from database.models import Finding, Scan, ScanStatus, SeverityLevel, ScheduledAudit, SubdomainAsset
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


class PaginationHelper:
    """Flask-SQLAlchemy compatible pagination helper for raw SQLAlchemy queries."""

    def __init__(self, page: int, per_page: int, total: int, items: list):
        self.page = page
        self.per_page = per_page
        self.total = total
        self.items = items
        self.pages = max(1, (total + per_page - 1) // per_page)
        self.has_prev = self.page > 1
        self.has_next = self.page < self.pages
        self.prev_num = self.page - 1 if self.has_prev else None
        self.next_num = self.page + 1 if self.has_next else None

    def iter_pages(self, left_edge=1, left_current=2, right_current=2, right_edge=1):
        last = 0
        for num in range(1, self.pages + 1):
            if (
                num <= left_edge
                or (num >= self.page - left_current and num <= self.page + right_current)
                or num > self.pages - right_edge
            ):
                if last + 1 != num:
                    yield None
                yield num
                last = num


@dashboard_bp.route("/", methods=["GET"])
def home():
    """Render public landing page with global platform metrics and masked recent public scans."""
    db = get_session()
    cleanup_stale_scans(db, max_age_seconds=120)

    # API JSON requests on / return standard public JSON payload
    is_json = (
        request.headers.get("Accept") == "application/json"
        or request.args.get("format") == "json"
    )
    if is_json:
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_all = (
            db.query(Scan)
            .filter(Scan.started_at >= thirty_days_ago)
            .order_by(Scan.started_at.asc())
            .all()
        )
        daily_counts: dict = {}
        for i in range(30):
            day = (datetime.utcnow() - timedelta(days=29 - i)).strftime("%Y-%m-%d")
            daily_counts[day] = 0
        for scan in recent_all:
            day_key = scan.started_at.strftime("%Y-%m-%d")
            if day_key in daily_counts:
                daily_counts[day_key] += 1

        return jsonify(
            {
                "total_scans": 0,
                "severity_totals": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "recent_scans": [],
                "posture_score": 100,
                "posture_tier": "Optimal",
                "sparkline_data": list(daily_counts.values()),
                "asset_inventory": [],
            }
        )

    # Global platform metrics
    global_audits = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count()
    global_total_findings = db.query(Finding).count()
    global_completed_scans = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).all()

    if global_completed_scans:
        global_scores = [
            _compute_posture_score(s.critical_count, s.high_count, s.medium_count, s.low_count)
            for s in global_completed_scans
        ]
        global_avg_posture = round(sum(global_scores) / len(global_scores))
    else:
        global_avg_posture = 85

    global_posture_tier = _score_tier(global_avg_posture)

    # Public recent scans feed — server-side pagination with 10 records per page
    page = request.args.get("page", 1, type=int)
    if not isinstance(page, int) or page < 1:
        page = 1
    per_page = 10

    completed_query = (
        db.query(Scan)
        .filter(Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.started_at.desc())
    )

    total_scans = completed_query.count()
    total_pages = max(1, (total_scans + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages

    offset = (page - 1) * per_page
    public_scans_models = completed_query.offset(offset).limit(per_page).all()

    recent_public_scans = []
    for s in public_scans_models:
        d = s.to_dict(user_id=None, guest_session_id=None)
        d["target_url"] = mask_domain(s.target_url, False)
        d["id"] = s.id
        d["posture_score"] = _compute_posture_score(
            s.critical_count, s.high_count, s.medium_count, s.low_count
        )
        recent_public_scans.append(d)

    scans_pagination = PaginationHelper(
        page=page,
        per_page=per_page,
        total=total_scans,
        items=recent_public_scans,
    )

    # 30-day activity graph
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_all = (
        db.query(Scan)
        .filter(Scan.started_at >= thirty_days_ago)
        .order_by(Scan.started_at.asc())
        .all()
    )
    daily_counts: dict = {}
    for i in range(30):
        day = (datetime.utcnow() - timedelta(days=29 - i)).strftime("%Y-%m-%d")
        daily_counts[day] = 0
    for scan in recent_all:
        day_key = scan.started_at.strftime("%Y-%m-%d")
        if day_key in daily_counts:
            daily_counts[day_key] += 1
    sparkline_data = list(daily_counts.values())

    return render_template(
        "home.html",
        global_audits=global_audits,
        global_avg_posture=global_avg_posture,
        global_posture_tier=global_posture_tier,
        discovered_assets=global_total_findings,
        recent_public_scans=recent_public_scans,
        scans_pagination=scans_pagination,
        sparkline_data=sparkline_data,
    )


@dashboard_bp.route("/dashboard", methods=["GET"])
def index():
    """Render tenant workspace dashboard summary metrics, asset inventory, and recent scans list."""
    db = get_session()
    cleanup_stale_scans(db, max_age_seconds=120)

    user_id = session.get("user_id")
    guest_id = (
        request.cookies.get("guest_device_id", "").strip()
        or session.get("guest_id", "")
        or session.get("guest_session_id", "")
    )
    is_guest = bool(session.get("is_guest") or request.cookies.get("guest_device_id"))
    is_authenticated = bool(user_id or is_guest or guest_id)

    is_json = (
        request.headers.get("Accept") == "application/json"
        or request.args.get("format") == "json"
    )

    if not is_authenticated:
        if is_json:
            return jsonify(
                {
                    "total_scans": 0,
                    "severity_totals": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "recent_scans": [],
                    "posture_score": 100,
                    "posture_tier": "Optimal",
                    "sparkline_data": [0] * 30,
                    "asset_inventory": [],
                }
            )
        return redirect(url_for("auth.login", reason="dashboard_required"))

    if user_id:
        base_query = db.query(Scan).filter(Scan.user_id == user_id)
        viewer_owns_all = True
    elif guest_id:
        base_query = db.query(Scan).filter(Scan.guest_session_id == guest_id)
        viewer_owns_all = True
    else:
        base_query = db.query(Scan).filter(False)
        viewer_owns_all = False

    total_scans = base_query.count()

    totals = {
        "critical": base_query.with_entities(func.sum(Scan.critical_count)).scalar() or 0,
        "high": base_query.with_entities(func.sum(Scan.high_count)).scalar() or 0,
        "medium": base_query.with_entities(func.sum(Scan.medium_count)).scalar() or 0,
        "low": base_query.with_entities(func.sum(Scan.low_count)).scalar() or 0,
        "info": base_query.with_entities(func.sum(Scan.info_count)).scalar() or 0,
    }

    completed_scans = base_query.filter(Scan.status == ScanStatus.COMPLETED).all()
    if completed_scans:
        individual_scores = [
            _compute_posture_score(
                s.critical_count, s.high_count, s.medium_count, s.low_count
            )
            for s in completed_scans
        ]
        posture_score = round(sum(individual_scores) / len(individual_scores))
    else:
        posture_score = 100
    posture_tier = _score_tier(posture_score)

    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_all = (
        base_query.filter(Scan.started_at >= thirty_days_ago)
        .order_by(Scan.started_at.asc())
        .all()
    )

    daily_counts: dict = {}
    for i in range(30):
        day = (datetime.utcnow() - timedelta(days=29 - i)).strftime("%Y-%m-%d")
        daily_counts[day] = 0
    for scan in recent_all:
        day_key = scan.started_at.strftime("%Y-%m-%d")
        if day_key in daily_counts:
            daily_counts[day_key] += 1

    sparkline_data = list(daily_counts.values())

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
        asset_inventory.append({
            "hostname": mask_domain(host, viewer_owns_all),
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

    # Query recurring schedules
    sched_query = db.query(ScheduledAudit)
    if user_id:
        sched_query = sched_query.filter(ScheduledAudit.user_id == user_id)
    schedules = [s.to_dict() for s in sched_query.all()]

    # Query subdomain assets
    sub_query = db.query(SubdomainAsset)
    if user_id:
        sub_query = sub_query.filter(SubdomainAsset.user_id == user_id)
    subdomain_assets = [sa.to_dict() for sa in sub_query.order_by(SubdomainAsset.id.desc()).all()]

    if is_json:
        return jsonify(
            {
                "total_scans": total_scans,
                "severity_totals": totals,
                "recent_scans": recent_scans,
                "posture_score": posture_score,
                "posture_tier": posture_tier,
                "sparkline_data": sparkline_data,
                "asset_inventory": asset_inventory,
                "schedules": schedules,
                "subdomain_assets": subdomain_assets,
            }
        )

    return render_template(
        "dashboard.html",
        is_anonymous=False,
        total_scans=total_scans,
        totals=totals,
        recent_scans=recent_scans,
        posture_score=posture_score,
        posture_tier=posture_tier,
        sparkline_data=sparkline_data,
        asset_inventory=asset_inventory,
        schedules=schedules,
        subdomain_assets=subdomain_assets,
    )
