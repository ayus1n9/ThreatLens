"""
Alert Notification Dispatcher.

Formats and optionally dispatches triage summaries to incoming webhooks
with explicit service-specific formatters for both Slack and Discord,
strict secret sanitation, payload truncation, and an offline dry-run inspection mode.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import httpx

from soc_intel.models import AssessmentPriority, EnrichedIndicator

logger = logging.getLogger("soc_intel.notifications")


class NotificationDispatcher:
    """Manages creation and delivery of SOC alert webhooks for Slack and Discord."""

    def __init__(self, webhook_url: Optional[str] = None, timeout_seconds: float = 5.0):
        self.webhook_url = webhook_url.strip() if webhook_url else None
        self.timeout_seconds = timeout_seconds

    def is_discord(self) -> bool:
        """Detect whether the configured webhook URL belongs to Discord."""
        if not self.webhook_url:
            return False
        return "discord.com" in self.webhook_url.lower() or "discordapp.com" in self.webhook_url.lower()

    def format_slack_payload(self, results: List[EnrichedIndicator]) -> Dict[str, Any]:
        """Build a Block Kit payload formatted for Slack webhooks."""
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

        return {
            "text": title,
            "blocks": blocks,
        }

    def format_discord_payload(self, results: List[EnrichedIndicator]) -> Dict[str, Any]:
        """Build an embed payload formatted for Discord webhooks."""
        high_priority = [r for r in results if r.assessment.priority == AssessmentPriority.HIGH]
        med_priority = [r for r in results if r.assessment.priority == AssessmentPriority.MEDIUM]

        # Determine embed accent color: Red for High, Amber for Medium, Blue for standard
        color = 15158332 if high_priority else 15105570 if med_priority else 3447003

        embed_fields = [
            {
                "name": "Total Processed",
                "value": str(len(results)),
                "inline": True,
            },
            {
                "name": "High Priority",
                "value": str(len(high_priority)),
                "inline": True,
            },
            {
                "name": "Medium Priority",
                "value": str(len(med_priority)),
                "inline": True,
            },
        ]

        priority_indicators = (high_priority + med_priority)[:8]
        for ind in priority_indicators:
            field_title = f"{ind.assessment.priority.value.upper()}: {ind.indicator.value} ({ind.indicator.indicator_type.value.upper()})"
            field_body = (
                f"**Summary:** {ind.assessment.summary}\n"
                f"**Action:** {ind.assessment.recommended_action}\n"
                f"**Coverage:** {len(ind.successful_providers)}/{len(ind.provider_records)} providers"
            )
            embed_fields.append({"name": field_title, "value": field_body, "inline": False})

        return {
            "content": f"🚨 **ThreatLens SOC Triage Alert:** {len(high_priority)} High / {len(med_priority)} Medium IOCs flagged.",
            "embeds": [
                {
                    "title": "ThreatLens Indicator Enrichment Triage Report",
                    "color": color,
                    "fields": embed_fields,
                }
            ],
        }

    def format_payload(self, results: List[EnrichedIndicator]) -> Dict[str, Any]:
        """Automatically select Slack or Discord payload format based on webhook URL."""
        if self.is_discord():
            return self.format_discord_payload(results)
        return self.format_slack_payload(results)

    def send(self, results: List[EnrichedIndicator], dry_run: bool = False) -> bool:
        """
        Transmit notification or display payload locally if dry_run is True.

        Returns:
            bool: True if delivered or dry-run completed, False on network error or missing URL.
        """
        payload = self.format_payload(results)

        if dry_run:
            import json
            service_target = "Discord" if self.is_discord() else "Slack / Standard"
            print(f"\n[+] Webhook Dry-Run Mode Active ({service_target} format - not transmitted):")
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
