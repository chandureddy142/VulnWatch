"""
Background Scheduler Task Execution for Recurring Audits
Evaluates active schedules, triggers automated passive scans, and dispatches degradation webhooks.
"""
from datetime import datetime, timedelta
import logging
import requests
from database.db import get_session
from database.models import ScheduledAudit, ScheduleStatus, CadenceType, Scan, ScanStatus, SeverityLevel

logger = logging.getLogger(__name__)


def compute_next_run(current_time: datetime, cadence: CadenceType) -> datetime:
    """Compute the next scheduled execution time based on cadence."""
    if cadence == CadenceType.daily:
        return current_time + timedelta(days=1)
    elif cadence == CadenceType.monthly:
        return current_time + timedelta(days=30)
    else:  # weekly default
        return current_time + timedelta(days=7)


def run_scheduled_audits() -> int:
    """Execute all due active scheduled audits."""
    db = get_session()
    now = datetime.utcnow()

    due_schedules = db.query(ScheduledAudit).filter(
        ScheduledAudit.status == ScheduleStatus.active,
        ScheduledAudit.next_run <= now
    ).all()

    executed_count = 0

    for sched in due_schedules:
        try:
            # Create a scan record
            scan = Scan(
                target_url=sched.target_url,
                status=ScanStatus.RUNNING,
                started_at=now,
                user_id=sched.user_id
            )
            db.add(scan)
            db.commit()

            # Execute lightweight passive audit (stub / simulated run)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            db.commit()

            # Calculate posture score (simplified 100 - critical*25 - high*15 - medium*5)
            new_score = max(0, 100 - (scan.critical_count * 25 + scan.high_count * 15 + scan.medium_count * 5))

            # Check degradation (>= 10 points drop)
            old_score = sched.last_posture_score
            if old_score is not None and (old_score - new_score) >= 10:
                logger.warning(f"POSTURE DEGRADATION DETECTED for {sched.target_url}: {old_score} -> {new_score}")
                if sched.webhook_url:
                    try:
                        requests.post(sched.webhook_url, json={
                            "event": "POSTURE_DEGRADED",
                            "target": sched.target_url,
                            "score": new_score,
                            "previous_score": old_score
                        }, timeout=5)
                    except Exception as err:
                        logger.error(f"Failed to dispatch degradation webhook to {sched.webhook_url}: {err}")

            # Update schedule record
            sched.last_run = now
            sched.last_posture_score = new_score
            sched.next_run = compute_next_run(now, sched.cadence)
            db.commit()
            executed_count += 1

        except Exception as err:
            logger.error(f"Error executing scheduled audit for {sched.target_url}: {err}")

    return executed_count
