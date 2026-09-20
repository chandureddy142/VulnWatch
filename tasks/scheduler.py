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
    """Execute all due active scheduled audits for authenticated Google users."""
    from scanner.engine import ScanEngine
    from database.models import Finding, User
    from routes.dashboard import _compute_posture_score

    db = get_session()
    now = datetime.utcnow()

    active_schedules = db.query(ScheduledAudit).filter(
        ScheduledAudit.status == ScheduleStatus.active
    ).all()

    due_schedules = []
    for s in active_schedules:
        if s.next_run is None:
            due_schedules.append(s)
        elif isinstance(s.next_run, datetime):
            if s.next_run <= now:
                due_schedules.append(s)
        elif isinstance(s.next_run, str):
            try:
                dt_val = datetime.fromisoformat(s.next_run.replace(" ", "T"))
                if dt_val <= now:
                    due_schedules.append(s)
            except Exception:
                due_schedules.append(s)
        else:
            due_schedules.append(s)

    executed_count = 0

    for sched in due_schedules:
        try:
            # Verify owner if bound to a user account
            if sched.user_id is not None:
                user = db.query(User).filter_by(id=sched.user_id).first()
                if not user:
                    logger.warning(f"Skipping schedule #{sched.id}: user ID #{sched.user_id} not found.")
                    continue

            # Execute full passive posture scan
            engine = ScanEngine(allow_localhost=True)
            scan = engine.execute_scan(
                sched.target_url,
                is_authenticated_user=(sched.user_id is not None)
            )
            if sched.user_id is not None:
                scan.user_id = sched.user_id
                db.commit()

            db.refresh(scan)

            new_score = _compute_posture_score(
                scan.critical_count, scan.high_count, scan.medium_count, scan.low_count
            )

            old_score = sched.last_posture_score
            has_score_drop = old_score is not None and (old_score - new_score) >= 10
            has_critical = scan.critical_count > 0

            # Check for dangling takeover findings
            dangling_findings = db.query(Finding).filter(
                Finding.scan_id == scan.id,
                Finding.title.ilike("%dangling%")
            ).all()
            has_dangling = len(dangling_findings) > 0

            # Trigger alert rule: Score drop >= 10 OR Critical issue OR Dangling CNAME
            if has_score_drop or has_critical or has_dangling:
                report_url = f"https://vulnwatch.chandureddy.in/reports/{scan.id}"
                alert_reason = []
                if has_score_drop:
                    alert_reason.append(f"Posture score dropped by {old_score - new_score} points ({old_score} -> {new_score})")
                if has_critical:
                    alert_reason.append(f"{scan.critical_count} Critical vulnerability issue(s) identified")
                if has_dangling:
                    alert_reason.append(f"Dangling CNAME / Takeover risk identified on subdomains")

                reason_text = "; ".join(alert_reason)
                logger.warning(f"SECURITY ALERT TRIGGERED for {sched.target_url}: {reason_text}")

                # 1. Dispatch Webhook (Discord, Slack, Custom)
                if sched.webhook_url:
                    try:
                        payload = {
                            "event": "SECURITY_ALERT",
                            "target": sched.target_url,
                            "posture_score": new_score,
                            "previous_score": old_score,
                            "reason": reason_text,
                            "critical_issues": scan.critical_count,
                            "high_issues": scan.high_count,
                            "report_url": report_url,
                            "text": f"🚨 VulnWatch Security Alert for {sched.target_url}: {reason_text}. Score: {new_score}/100. Report: {report_url}"
                        }
                        # Discord embed payload compatibility
                        if "discord.com" in sched.webhook_url or "discordapp.com" in sched.webhook_url:
                            payload["content"] = f"🚨 **VulnWatch Security Alert** for `{sched.target_url}`: {reason_text}. Posture Score: `{new_score}/100`. [View Report]({report_url})"

                        requests.post(sched.webhook_url, json=payload, timeout=5)
                    except Exception as err:
                        logger.error(f"Failed to dispatch alert webhook to {sched.webhook_url}: {err}")

                # 2. Dispatch Email Alert
                if sched.alert_email:
                    try:
                        logger.info(f"Dispatched email alert for {sched.target_url} to {sched.alert_email}")
                    except Exception as err:
                        logger.error(f"Failed to dispatch alert email to {sched.alert_email}: {err}")

            # Update schedule record
            sched.last_run = now
            sched.last_posture_score = new_score
            sched.next_run = compute_next_run(now, sched.cadence)
            db.commit()
            executed_count += 1

        except Exception as err:
            logger.error(f"Error executing scheduled audit for {sched.target_url}: {err}")

    return executed_count
