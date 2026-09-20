"""
Global Search (⌘K) Palette API Endpoint
Searches past scan targets, findings, and platform quick navigation items.
"""
from flask import Blueprint, jsonify, request, session
from database.db import get_session
from database.models import Scan

search_bp = Blueprint("search", __name__)


@search_bp.route("/api/quick-search", methods=["GET"])
def quick_search():
    """Return JSON search results matching query 'q' across scans and system navigation."""
    query_str = request.args.get("q", "").strip().lower()

    # System Quick Navigation Actions
    system_actions = [
        {"title": "Launch New Audit", "category": "Navigation", "url": "/scanner", "icon": "zap"},
        {"title": "Executive Dashboard", "category": "Navigation", "url": "/dashboard", "icon": "home"},
        {"title": "API Documentation", "category": "Navigation", "url": "/api/docs", "icon": "code"},
        {"title": "Platform Settings", "category": "Navigation", "url": "/settings", "icon": "sliders"},
    ]

    matched_actions = [
        a for a in system_actions if not query_str or query_str in a["title"].lower()
    ]

    # Query past audit scans
    db = get_session()
    user_id = session.get("user_id")

    query = db.query(Scan)
    if user_id:
        query = query.filter(Scan.user_id == user_id)
    else:
        guest_device_id = request.cookies.get("guest_device_id", "").strip() or session.get("guest_id", "")
        if guest_device_id:
            query = query.filter(Scan.guest_session_id == guest_device_id)

    if query_str:
        query = query.filter(Scan.target_url.ilike(f"%{query_str}%"))

    scans = query.order_by(Scan.started_at.desc()).limit(10).all()

    matched_scans = []
    for scan in scans:
        matched_scans.append({
            "id": scan.id,
            "title": scan.target_url,
            "category": "Audits",
            "url": f"/reports/{scan.id}",
            "status": scan.status.value if scan.status else "COMPLETED",
            "date": scan.started_at.strftime("%Y-%m-%d %H:%M") if scan.started_at else "N/A"
        })

    return jsonify({
        "query": query_str,
        "results": {
            "navigation": matched_actions,
            "audits": matched_scans
        }
    })
