"""Best-effort outbound notifications (currently: Slack incoming webhook).

Never allowed to raise or slow down the request path noticeably: any
network failure, bad webhook URL, or timeout is logged and swallowed.
"""
import logging

import httpx

from app.core.config import get_settings
from app.models.analysis import Analysis

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(4.0, connect=2.0)


def notify_if_critical(analysis: Analysis) -> None:
    """Post a short Slack message when an analysis is classified Critical.

    No-op when SLACK_WEBHOOK_URL is not configured or the risk level is not
    Critical. Any failure while posting is caught and logged -- this must
    never break analysis creation.
    """
    if analysis.risk_level != "Critical":
        return

    settings = get_settings()
    webhook_url = (settings.SLACK_WEBHOOK_URL or "").strip()
    if not webhook_url:
        return

    summary = (analysis.summary or "").strip()
    if len(summary) > 300:
        summary = summary[:297] + "..."

    text = (
        f":rotating_light: *Critical* triage result (id `{analysis.id}`)\n"
        f"Classification: *{analysis.classification}* | Confidence: {analysis.confidence}%\n"
        f"{summary}"
    )

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(webhook_url, json={"text": text})
            if resp.status_code >= 400:
                logger.warning(
                    "Slack webhook returned status %s for analysis %s",
                    resp.status_code,
                    analysis.id,
                )
    except httpx.HTTPError as exc:
        logger.warning("Slack webhook notification failed for analysis %s: %s", analysis.id, exc)
    except Exception as exc:  # noqa: BLE001 - notifications must never break analysis creation
        logger.warning("Unexpected error sending Slack notification for analysis %s: %s", analysis.id, exc)
