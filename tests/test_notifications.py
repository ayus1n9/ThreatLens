"""Unit tests for the Alert Notification Dispatcher and Webhook payloads."""

import pytest
import respx
import httpx
from soc_intel.models import (
    AssessmentPriority,
    AssessmentResult,
    EnrichedIndicator,
    NormalizedIndicator,
    OverallEnrichmentStatus,
)
from soc_intel.notifications import NotificationDispatcher
from soc_intel.validators import IndicatorType


@pytest.fixture
def sample_triage_results():
    return [
        EnrichedIndicator(
            indicator=NormalizedIndicator(value="198.51.100.5", indicator_type=IndicatorType.IPV4),
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            assessment=AssessmentResult(
                priority=AssessmentPriority.HIGH,
                summary="High priority: Active C2",
                recommended_action="Block at firewall",
            ),
        ),
        EnrichedIndicator(
            indicator=NormalizedIndicator(value="1.1.1.1", indicator_type=IndicatorType.IPV4),
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            assessment=AssessmentResult(
                priority=AssessmentPriority.LOW,
                summary="Low priority: Clean",
                recommended_action="Monitor",
            ),
        ),
    ]


class TestNotifications:
    """Test webhook payload formatting, dry-run, and network handling."""

    def test_format_payload_structure(self, sample_triage_results):
        dispatcher = NotificationDispatcher(webhook_url="https://example.com/alerts/webhook")
        payload = dispatcher.format_payload(sample_triage_results)

        assert "ThreatLens SOC Alert" in payload["text"]
        assert len(payload["blocks"]) >= 3
        # Ensure indicator was included
        found_ioc = any("198.51.100.5" in str(b) for b in payload["blocks"])
        assert found_ioc is True

    def test_dry_run_does_not_send_http(self, sample_triage_results, capsys):
        dispatcher = NotificationDispatcher(webhook_url=None)
        # Should succeed without error even without URL
        success = dispatcher.send(sample_triage_results, dry_run=True)
        assert success is True
        captured = capsys.readouterr()
        assert "Webhook Dry-Run Mode Active" in captured.out
        assert "198.51.100.5" in captured.out

    def test_missing_webhook_url_returns_false(self, sample_triage_results):
        dispatcher = NotificationDispatcher(webhook_url=None)
        assert dispatcher.send(sample_triage_results, dry_run=False) is False

    @respx.mock
    def test_successful_webhook_transmission(self, sample_triage_results):
        webhook_url = "https://example.com/alerts/webhook"
        route = respx.post(webhook_url).mock(return_value=httpx.Response(200, text="ok"))

        dispatcher = NotificationDispatcher(webhook_url=webhook_url)
        assert dispatcher.send(sample_triage_results, dry_run=False) is True
        assert route.called

    @respx.mock
    def test_failed_webhook_http_error(self, sample_triage_results):
        webhook_url = "https://example.com/alerts/webhook"
        respx.post(webhook_url).mock(return_value=httpx.Response(500, text="internal error"))

        dispatcher = NotificationDispatcher(webhook_url=webhook_url)
        assert dispatcher.send(sample_triage_results, dry_run=False) is False
