"""
P0 and P1 audit tests verifying fixes for critical findings:
1. Provider data absence vs genuine zero detection (no false LOW).
2. All-NOT_FOUND batch reports valid lookup with unindexed intelligence.
3. Special-purpose / shared-address IP rejection (RFC 6598 CGNAT, documentation, ULA).
4. Malformed provider JSON handling.
5. Slack and Discord payload structures.
6. Custom .env missing file error.
7. End-to-end CLI exit code semantics.
"""

import json
from pathlib import Path
import pytest
import respx
import httpx

from soc_intel.assessment import AssessmentEngine
from soc_intel.cli import main
from soc_intel.config import load_config
from soc_intel.models import (
    AssessmentConfidence,
    AssessmentPriority,
    EnrichedIndicator,
    NormalizedIndicator,
    OverallEnrichmentStatus,
    ProviderEnrichmentRecord,
)
from soc_intel.notifications import NotificationDispatcher
from soc_intel.providers.abuseipdb import AbuseIPDBClient
from soc_intel.providers.base import ProviderStatus
from soc_intel.providers.virustotal import VirusTotalClient
from soc_intel.validators import (
    IndicatorType,
    ValidatedIndicator,
    classify_ip_address,
    parse_indicator_file,
    validate_single_indicator,
)


class TestCritical1And4_MissingDataAndConfidence:
    """Critical 1: Ensure missing provider data is never treated as zero detections."""

    def test_virustotal_timeout_abuseipdb_zero_is_not_low(self):
        """When VT times out and AbuseIPDB reports 0 score, priority must be UNDETERMINED, not LOW."""
        indicator = NormalizedIndicator(value="198.51.100.99", indicator_type=IndicatorType.IPV4)
        enriched = EnrichedIndicator(
            indicator=indicator,
            enrichment_status=OverallEnrichmentStatus.PARTIAL,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.TIMEOUT,
                    error_message="Gateway timeout",
                ),
                ProviderEnrichmentRecord(
                    provider_name="AbuseIPDB",
                    status=ProviderStatus.SUCCESS,
                    reputation_score=0.0,
                    detections=0,
                ),
            ],
        )

        res = AssessmentEngine.evaluate(enriched)
        assert res.priority == AssessmentPriority.UNDETERMINED
        assert res.confidence == AssessmentConfidence.LIMITED
        assert any("Partial intelligence" in c for c in res.caveats)
        assert any("missing data was NOT treated as zero detections" in c for c in res.caveats)

    def test_both_providers_genuine_zero_is_low(self):
        """When BOTH VT and AbuseIPDB respond with zero detections, priority is LOW."""
        indicator = NormalizedIndicator(value="1.1.1.1", indicator_type=IndicatorType.IPV4)
        enriched = EnrichedIndicator(
            indicator=indicator,
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.SUCCESS,
                    detections=0,
                ),
                ProviderEnrichmentRecord(
                    provider_name="AbuseIPDB",
                    status=ProviderStatus.SUCCESS,
                    reputation_score=0.0,
                    detections=0,
                ),
            ],
        )

        res = AssessmentEngine.evaluate(enriched)
        assert res.priority == AssessmentPriority.LOW
        assert res.confidence == AssessmentConfidence.HIGH
        assert any("Zero findings does not prove the indicator is safe" in c for c in res.caveats)


class TestCritical3_NotFoundHandling:
    """Critical 3: Distinguish NOT_FOUND (unindexed) from provider failure or clean result."""

    def test_all_not_found_is_undetermined_with_novel_caveat(self):
        indicator = NormalizedIndicator(value="198.51.100.100", indicator_type=IndicatorType.IPV4)
        enriched = EnrichedIndicator(
            indicator=indicator,
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.NOT_FOUND,
                    error_message="Not found",
                ),
                ProviderEnrichmentRecord(
                    provider_name="AbuseIPDB",
                    status=ProviderStatus.NOT_FOUND,
                    error_message="Not found",
                ),
            ],
        )

        res = AssessmentEngine.evaluate(enriched)
        assert res.priority == AssessmentPriority.UNDETERMINED
        assert "unindexed" in res.summary.lower()
        assert any("An unindexed (404 Not Found) indicator is NOT clean or benign" in c for c in res.caveats)

    def test_one_not_found_one_success_malicious(self):
        indicator = NormalizedIndicator(value="198.51.100.101", indicator_type=IndicatorType.IPV4)
        enriched = EnrichedIndicator(
            indicator=indicator,
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.NOT_FOUND,
                ),
                ProviderEnrichmentRecord(
                    provider_name="AbuseIPDB",
                    status=ProviderStatus.SUCCESS,
                    reputation_score=95.0,
                    detections=20,
                ),
            ],
        )

        res = AssessmentEngine.evaluate(enriched)
        assert res.priority == AssessmentPriority.HIGH
        assert res.confidence == AssessmentConfidence.MEDIUM
        assert any("Unindexed: VirusTotal" in c for c in res.caveats)


class TestCritical2_RoutabilityAndSpecialRanges:
    """Critical 2: Comprehensive validation of special-purpose and shared IP ranges."""

    @pytest.mark.parametrize(
        "ip,expected_desc",
        [
            ("100.64.0.1", "Shared Address Space / CGNAT (RFC 6598)"),
            ("100.127.255.254", "Shared Address Space / CGNAT (RFC 6598)"),
            ("169.254.1.1", "Link-local address (RFC 3927)"),
            ("192.0.2.1", "TEST-NET-1 documentation (RFC 5737)"),
            ("198.51.100.5", "TEST-NET-2 documentation (RFC 5737)"),
            ("203.0.113.10", "TEST-NET-3 documentation (RFC 5737)"),
            ("198.18.0.1", "Benchmarking (RFC 2544)"),
            ("224.0.0.1", "Multicast (RFC 5771)"),
            ("240.0.0.1", "Reserved for future use (RFC 1112)"),
            ("::ffff:192.0.2.1", "IPv4-mapped address (RFC 4291)"),
            ("2001:db8::1", "Documentation prefix (RFC 3849)"),
            ("fc00::1", "Unique Local Address (ULA) (RFC 4193)"),
            ("fe80::1", "Link-Local Unicast (RFC 4291)"),
        ],
    )
    def test_special_ips_rejected_by_default(self, ip, expected_desc):
        is_valid, itype, is_public, scope_note = classify_ip_address(ip)
        assert is_valid is True
        assert is_public is False
        assert expected_desc in scope_note

        with pytest.raises(ValueError, match="non-routable/special-purpose IP"):
            validate_single_indicator(ip, allow_private=False)

    def test_special_ip_permitted_with_flag(self):
        res = validate_single_indicator("100.64.0.1", allow_private=True)
        assert res.normalized_value == "100.64.0.1"
        assert res.is_public is False


class TestProviderSchemaValidation:
    """Tests for malformed provider JSON payloads and type errors."""

    @respx.mock
    def test_virustotal_malformed_json_returns_error(self):
        client = VirusTotalClient(api_key="mock_key")
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
            return_value=httpx.Response(200, text="not valid json {{{")
        )
        res = client.lookup(ValidatedIndicator("8.8.8.8", "8.8.8.8", IndicatorType.IPV4))
        assert res.status == ProviderStatus.ERROR
        assert "Malformed JSON" in res.error_message

    @respx.mock
    def test_virustotal_unexpected_schema_returns_error(self):
        client = VirusTotalClient(api_key="mock_key")
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
            return_value=httpx.Response(200, json={"unexpected_key": 123})
        )
        res = client.lookup(ValidatedIndicator("8.8.8.8", "8.8.8.8", IndicatorType.IPV4))
        assert res.status == ProviderStatus.ERROR
        assert "missing top-level 'data'" in res.error_message

    @respx.mock
    def test_abuseipdb_missing_score_returns_error(self):
        client = AbuseIPDBClient(api_key="mock_key")
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(200, json={"data": {"ipAddress": "8.8.8.8"}})
        )
        res = client.lookup(ValidatedIndicator("8.8.8.8", "8.8.8.8", IndicatorType.IPV4))
        assert res.status == ProviderStatus.ERROR
        assert "missing 'abuseConfidenceScore'" in res.error_message


class TestWebhookSlackAndDiscordFormats:
    """Verify distinct formatting between Slack and Discord webhooks."""

    def test_slack_payload_format(self):
        dispatcher = NotificationDispatcher(webhook_url="https://hooks.slack.com/services/XXX")
        payload = dispatcher.format_payload([])
        assert "blocks" in payload
        assert "text" in payload
        assert "embeds" not in payload

    def test_discord_payload_format(self):
        dispatcher = NotificationDispatcher(webhook_url="https://discord.com/api/webhooks/123/abc")
        payload = dispatcher.format_payload([])
        assert "embeds" in payload
        assert "content" in payload
        assert "blocks" not in payload


class TestConfigAndCLIExitCodes:
    """Verify missing .env path error and CLI exit status semantics."""

    def test_missing_custom_env_raises_error(self, tmp_path: Path):
        non_existent = tmp_path / "does_not_exist.env"
        with pytest.raises(FileNotFoundError, match="Specified configuration file does not exist"):
            load_config(non_existent)

    def test_cli_partial_validation_exit_code_1(self, tmp_path: Path):
        # 8.8.8.8 is valid, 10.0.0.1 is rejected
        f = tmp_path / "mixed.txt"
        f.write_text("8.8.8.8\n10.0.0.1\n")
        code = main(["validate", "--input", str(f)])
        assert code == 1  # 1 indicates partial acceptance / warnings

    def test_cli_complete_validation_exit_code_0(self, tmp_path: Path):
        f = tmp_path / "clean.txt"
        f.write_text("8.8.8.8\n1.1.1.1\n")
        code = main(["validate", "--input", str(f)])
        assert code == 0
