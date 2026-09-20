"""
Scheduled Audits API & Management Blueprint
Allows authenticated users to create, list, toggle, and delete recurring audit schedules.
"""
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, session
from database.db import get_session
from database.models import ScheduledAudit, ScheduleStatus, CadenceType
from services.auth import require_api_key_or_browser
from tasks.scheduler import compute_next_run

schedules_bp = Blueprint("schedules", __name__, url_prefix="/schedules")


@schedules_bp.route("/", methods=["GET"])
def list_schedules():
    """List all scheduled audits for current user or session."""
    db = get_session()
    user_id = session.get("user_id")

    query = db.query(ScheduledAudit)
    if user_id:
        query = query.filter(ScheduledAudit.user_id == user_id)

    schedules = query.order_by(ScheduledAudit.id.desc()).all()
    return jsonify({"schedules": [s.to_dict() for s in schedules]})


@schedules_bp.route("/create", methods=["POST"])
def create_schedule():
    """Create a new recurring audit schedule (Google authenticated users only)."""
    user_id = session.get("user_id")
    if not user_id or session.get("is_guest"):
        return jsonify({"error": "Google Sign-In required to configure alert webhooks and automated schedules"}), 403

    data = request.get_json() or request.form
    target_url = data.get("target_url", "").strip()
    cadence_str = data.get("cadence", "weekly").strip().lower()
    alert_email = data.get("alert_email", "").strip()
    webhook_url = data.get("webhook_url", "").strip()

    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    try:
        cadence_enum = CadenceType(cadence_str)
    except ValueError:
        cadence_enum = CadenceType.weekly

    now = datetime.utcnow()
    next_run = compute_next_run(now, cadence_enum)

    db = get_session()
    schedule = ScheduledAudit(
        user_id=user_id,
        target_url=target_url,
        cadence=cadence_enum,
        last_run=None,
        next_run=next_run,
        alert_email=alert_email or None,
        webhook_url=webhook_url or None,
        status=ScheduleStatus.active
    )
    db.add(schedule)
    db.commit()

    return jsonify({"message": "Scheduled audit created.", "schedule": schedule.to_dict()}), 201


@schedules_bp.route("/<int:sched_id>/toggle", methods=["POST"])
def toggle_schedule(sched_id: int):
    """Toggle active/paused status of a scheduled audit."""
    db = get_session()
    schedule = db.query(ScheduledAudit).filter_by(id=sched_id).first()
    if not schedule:
        return jsonify({"error": "Schedule not found"}), 404

    if schedule.status == ScheduleStatus.active:
        schedule.status = ScheduleStatus.paused
    else:
        schedule.status = ScheduleStatus.active

    db.commit()
    return jsonify({"message": "Schedule status updated.", "schedule": schedule.to_dict()})


@schedules_bp.route("/<int:sched_id>", methods=["DELETE"])
@schedules_bp.route("/<int:sched_id>/delete", methods=["POST", "DELETE"])
def delete_schedule(sched_id: int):
    """Delete a scheduled audit."""
    db = get_session()
    schedule = db.query(ScheduledAudit).filter_by(id=sched_id).first()
    if not schedule:
        return jsonify({"error": "Schedule not found"}), 404

    db.delete(schedule)
    db.commit()
    return jsonify({"message": "Schedule deleted successfully.", "id": sched_id})
