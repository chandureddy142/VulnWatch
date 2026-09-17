from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse
from flask import Blueprint, jsonify, render_template, request, redirect, url_for
from sqlalchemy import func
from database.db import get_session
from database.models import Finding, Scan, ScanStatus, SeverityLevel
from scanner.engine import cleanup_stale_scans

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

    total_scans = db.query(Scan).count()

    # Aggregate severity totals across all scans
    totals = {
        "critical": db.query(func.sum(Scan.critical_count)).scalar() or 0,
        "high": db.query(func.sum(Scan.high_count)).scalar() or 0,
        "medium": db.query(func.sum(Scan.medium_count)).scalar() or 0,
        "low": db.query(func.sum(Scan.low_count)).scalar() or 0,
        "info": db.query(func.sum(Scan.info_count)).scalar() or 0,
    }

    # Security Posture Score — average per-scan score across COMPLETED scans
    # Computing on aggregate totals collapses to 0 when finding counts are large;
    # averaging individual scan scores gives a meaningful representative metric.
    completed_scans = (
        db.query(Scan)
        .filter(Scan.status == ScanStatus.COMPLETED)
        .all()
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

    # 30-day daily scan volume for sparkline
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_all = (
        db.query(Scan)
        .filter(Scan.started_at >= thirty_days_ago)
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
    all_scans = db.query(Scan).all()
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
            "hostname": host,
            "scan_count": len(scans_list),
            "last_scanned_at": latest_scan.started_at.strftime("%Y-%m-%d %H:%M"),
            "latest_scan_id": latest_scan.id,
            "latest_status_code": latest_scan.status_code or "N/A",
            "latest_posture_score": latest_score,
            "latest_posture_tier": _score_tier(latest_score),
            "critical_count": latest_scan.critical_count,
            "high_count": latest_scan.high_count,
        })
    asset_inventory.sort(key=lambda x: x["scan_count"], reverse=True)

    recent_scans_models = (
        db.query(Scan).order_by(Scan.started_at.desc()).limit(50).all()
    )
    recent_scans = []
    for s in recent_scans_models:
        d = s.to_dict()
        d["recurrence"] = target_freq.get(s.target_url, 1)
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
        total_scans=total_scans,
        totals=totals,
        recent_scans=recent_scans,
        posture_score=posture_score,
        posture_tier=posture_tier,
        sparkline_data=sparkline_data,
        asset_inventory=asset_inventory,
    )
