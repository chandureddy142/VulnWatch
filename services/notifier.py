"""
WebGuard Webhook Notifier
Dispatches JSON alert payloads to Slack or Discord webhooks when
Critical or High severity findings are identified in a scan.
"""
import json
import urllib.request
import urllib.error
from typing import Optional


def dispatch_webhook(
    scan_id: int,
    target_url: str,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    posture_score: int,
    webhook_url: Optional[str],
) -> bool:
    """
    Post a JSON security alert to a Slack or Discord webhook.

    Only fires when Critical or High findings are present and a webhook URL is configured.

    Args:
        scan_id: The WebGuard scan ID.
        target_url: The audited target URL.
        critical_count: Number of Critical findings.
        high_count: Number of High findings.
        medium_count: Number of Medium findings.
        low_count: Number of Low findings.
        posture_score: Computed security posture score (0-100).
        webhook_url: The Slack/Discord webhook URL to post to.

    Returns:
        True if the webhook was dispatched successfully, False otherwise.
    """
    if not webhook_url:
        return False

    if critical_count == 0 and high_count == 0:
        return False  # Only alert on Critical/High findings

    score_tier = _score_tier(posture_score)

    # Build a message compatible with both Slack and Discord
    # Slack uses "text" at top level; Discord uses "content"
    alert_text = (
        f"🚨 *WebGuard Security Alert* — Scan #{scan_id}\n"
        f"Target: `{target_url}`\n"
        f"Posture Score: *{posture_score}/100* ({score_tier})\n"
        f"Critical: *{critical_count}*  |  High: *{high_count}*  "
        f"|  Medium: {medium_count}  |  Low: {low_count}\n"
        f"View results: `/reports/{scan_id}`"
    )

    payload = {
        "text": alert_text,       # Slack format
        "content": alert_text,    # Discord format
        "username": "WebGuard Auditor",
        "icon_emoji": ":shield:",
    }

    payload_bytes = json.dumps(payload).encode("utf-8")

    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status in (200, 204)
    except (urllib.error.URLError, Exception):
        # Gracefully no-op on any network failure — don't break the scan flow
        return False


def _score_tier(score: int) -> str:
    if score >= 90:
        return "Optimal"
    elif score >= 70:
        return "Moderate Risk"
    elif score >= 50:
        return "Elevated Risk"
    return "Critical Attention Required"
