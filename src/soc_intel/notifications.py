"""
Alert Notification Dispatcher.

Formats and optionally dispatches triage summaries to incoming webhooks
(Slack or Discord) with strict secret sanitation, payload truncation,
and an offline dry-run inspection mode.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import httpx

from soc_intel.models import AssessmentPriority, EnrichedIndicator

logger = logging.getLogger("soc_intel.notifications")


class NotificationDispatcher:
    """Manages creation and delivery of SOC alert webhooks."""

    def __init__(self, webhook_url: Optional[str] = None, timeout_seconds: float = 5.0):
        self.webhook_url = webhook_url.strip() if webhook_url else None
        self.timeout_seconds = timeout_seconds

    def format_payload(self, results: List[EnrichedIndicator]) -> Dict[str, Any]:
        """
        Build an alert payload tailored for SOC notifications.
        Omits sensitive raw API responses or credentials.
        """
        high_priority = [r for r in results if r.assessment.priority == AssessmentPriority.HIGH]
        med_priority = [r for r in results if r.assessment.priority == AssessmentPriority.MEDIUM]

        title = f":warning: ThreatLens SOC Alert: {len(high_priority)} High / {len(med_priority)} Medium Priority IOCs"
        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "ThreatLens Triage Alert", "emoji": True},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Total Indicators Processed:* {len(results)}\n"
                        f"*High Priority (Containment Needed):* {len(high_priority)}\n"
                        f"*Medium Priority (Investigation Needed):* {len(med_priority)}"
                    ),
                },
            },
            {"type": "divider"},
        ]

        # Highlight high & medium indicators (cap to top 10 to prevent chat flood)
        priority_indicators = (high_priority + med_priority)[:10]
        for ind in priority_indicators:
            badge = ":red_circle: HIGH" if ind.assessment.priority == AssessmentPriority.HIGH else ":large_yellow_circle: MEDIUM"
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{badge} *`{ind.indicator.value}`* ({ind.indicator.indicator_type.value.upper()})\n"
                            f"> *Summary:* {ind.assessment.summary}\n"
                            f"> *Recommended Action:* {ind.assessment.recommended_action}\n"
                            f"> *Coverage:* {len(ind.successful_providers)}/{len(ind.provider_records)} providers"
                        ),
                    },
                }
            )

        # Fallback text for Discord or standard webhook endpoints
        return {
            "text": title,
            "blocks": blocks,
        }

    def send(self, results: List[EnrichedIndicator], dry_run: bool = False) -> bool:
        """
        Transmit notification or display payload locally if dry_run is True.
        
        Returns:
            bool: True if delivered or dry-run completed, False on network error or missing URL.
        """
        payload = self.format_payload(results)

        if dry_run:
            import json
            print("\n[+] Webhook Dry-Run Mode Active (Notification not transmitted):")
            print(json.dumps(payload, indent=2))
            return True

        if not self.webhook_url:
            logger.warning("Notification requested but ALERT_WEBHOOK_URL is not configured.")
            return False

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(self.webhook_url, json=payload)
                if resp.status_code in (200, 204):
                    logger.info("Alert webhook successfully dispatched.")
                    return True
                else:
                    logger.error("Alert webhook failed with status code %s: %s", resp.status_code, resp.text)
                    return False
        except Exception as exc:
            logger.error("Failed to send webhook notification: %s", exc)
            return False
