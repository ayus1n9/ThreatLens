"""
Mocked unit tests for VirusTotal and AbuseIPDB provider clients.

Uses respx to simulate HTTP status codes, rate limits, timeouts, and JSON payloads
without making any live external network requests.
"""

import httpx
import pytest
import respx
from soc_intel.providers.abuseipdb import AbuseIPDBClient
from soc_intel.providers.base import ProviderStatus
from soc_intel.providers.virustotal import VirusTotalClient
from soc_intel.validators import IndicatorType, ValidatedIndicator


@pytest.fixture
def sample_ip_indicator():
    return ValidatedIndicator(
        raw_value="198.51.100.1",
        normalized_value="198.51.100.1",
        indicator_type=IndicatorType.IPV4,
        is_public=True,
    )


@pytest.fixture
def sample_hash_indicator():
    return ValidatedIndicator(
        raw_value="44d88612fea8a8f36de82e1278abb02f",
        normalized_value="44d88612fea8a8f36de82e1278abb02f",
        indicator_type=IndicatorType.MD5,
        is_public=True,
    )


class TestVirusTotalClient:
    """Tests for VirusTotalClient under various HTTP responses."""

    def test_unconfigured_api_key(self, sample_ip_indicator):
        client = VirusTotalClient(api_key=None)
        res = client.lookup(sample_ip_indicator)
        assert res.status == ProviderStatus.UNCONFIGURED
        assert "not configured" in res.error_message

    @respx.mock
    def test_successful_ip_lookup(self, sample_ip_indicator):
        client = VirusTotalClient(api_key="mock_vt_key", timeout_seconds=2.0)
        route = respx.get("https://www.virustotal.com/api/v3/ip_addresses/198.51.100.1").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 8,
                                "suspicious": 2,
                                "harmless": 60,
                                "undetected": 10,
                            },
                            "reputation": -25,
                            "tags": ["c2", "tor-exit"],
                            "last_analysis_date": 1690000000,
                        }
                    }
                },
            )
        )

        res = client.lookup(sample_ip_indicator)
        assert route.called
        assert res.status == ProviderStatus.SUCCESS
        assert res.http_status_code == 200
        assert res.detections == 10  # 8 malicious + 2 suspicious
        assert res.total_evaluators == 80
        assert res.reputation_score == -25.0
        assert "c2" in res.tags

    @respx.mock
    def test_successful_hash_lookup(self, sample_hash_indicator):
        client = VirusTotalClient(api_key="mock_vt_key", timeout_seconds=2.0)
        route = respx.get("https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 45,
                                "suspicious": 1,
                                "harmless": 0,
                                "undetected": 24,
                            },
                            "reputation": -80,
                            "tags": ["trojan", "ransomware"],
                        }
                    }
                },
            )
        )

        res = client.lookup(sample_hash_indicator)
        assert route.called
        assert res.status == ProviderStatus.SUCCESS
        assert res.detections == 46
        assert "trojan" in res.tags

    @respx.mock
    def test_rate_limit_429(self, sample_ip_indicator):
        client = VirusTotalClient(api_key="mock_vt_key", timeout_seconds=2.0)
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/198.51.100.1").mock(
            return_value=httpx.Response(429, json={"error": {"message": "Quota exceeded"}})
        )

        res = client.lookup(sample_ip_indicator)
        assert res.status == ProviderStatus.RATE_LIMITED
        assert res.http_status_code == 429
        assert "rate limit" in res.error_message.lower()

    @respx.mock
    def test_auth_error_401(self, sample_ip_indicator):
        client = VirusTotalClient(api_key="invalid_key", timeout_seconds=2.0)
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/198.51.100.1").mock(
            return_value=httpx.Response(401, json={"error": {"message": "Wrong API key"}})
        )

        res = client.lookup(sample_ip_indicator)
        assert res.status == ProviderStatus.AUTH_ERROR
        assert res.http_status_code == 401

    @respx.mock
    def test_not_found_404(self, sample_ip_indicator):
        client = VirusTotalClient(api_key="mock_vt_key", timeout_seconds=2.0)
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/198.51.100.1").mock(
            return_value=httpx.Response(404, json={"error": {"message": "Not found"}})
        )

        res = client.lookup(sample_ip_indicator)
        assert res.status == ProviderStatus.NOT_FOUND
        assert res.http_status_code == 404

    @respx.mock
    def test_timeout(self, sample_ip_indicator):
        client = VirusTotalClient(api_key="mock_vt_key", timeout_seconds=0.1)
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/198.51.100.1").mock(
            side_effect=httpx.TimeoutException("Read timeout")
        )

        res = client.lookup(sample_ip_indicator)
        assert res.status == ProviderStatus.TIMEOUT
        assert "timed out" in res.error_message


class TestAbuseIPDBClient:
    """Tests for AbuseIPDBClient."""

    def test_hash_unsupported_rejection(self, sample_hash_indicator):
        client = AbuseIPDBClient(api_key="mock_abuse_key")
        res = client.lookup(sample_hash_indicator)
        assert res.status == ProviderStatus.UNSUPPORTED
        assert "does not support file hashes" in res.error_message

    def test_unconfigured_api_key(self, sample_ip_indicator):
        client = AbuseIPDBClient(api_key=None)
        res = client.lookup(sample_ip_indicator)
        assert res.status == ProviderStatus.UNCONFIGURED
        assert "not configured" in res.error_message

    @respx.mock
    def test_successful_ip_lookup(self, sample_ip_indicator):
        client = AbuseIPDBClient(api_key="mock_abuse_key", timeout_seconds=2.0)
        route = respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": "198.51.100.1",
                        "abuseConfidenceScore": 85,
                        "totalReports": 42,
                        "numDistinctUsers": 15,
                        "lastReportedAt": "2026-10-09T18:00:00+00:00",
                        "countryCode": "RU",
                        "usageType": "Data Center/Web Hosting/Transit",
                        "isp": "BadHost LLC",
                    }
                },
            )
        )

        res = client.lookup(sample_ip_indicator)
        assert route.called
        assert res.status == ProviderStatus.SUCCESS
        assert res.http_status_code == 200
        assert res.detections == 42
        assert res.total_evaluators == 15
        assert res.reputation_score == 85.0
        assert any("ISP: BadHost LLC" in tag for tag in res.tags)

    @respx.mock
    def test_rate_limit_429(self, sample_ip_indicator):
        client = AbuseIPDBClient(api_key="mock_abuse_key")
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(429, json={"errors": [{"detail": "Daily rate limit exceeded"}]})
        )

        res = client.lookup(sample_ip_indicator)
        assert res.status == ProviderStatus.RATE_LIMITED
        assert res.http_status_code == 429

    @respx.mock
    def test_auth_error_401(self, sample_ip_indicator):
        client = AbuseIPDBClient(api_key="invalid_key")
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(401, json={"errors": [{"detail": "Authentication failed"}]})
        )

        res = client.lookup(sample_ip_indicator)
        assert res.status == ProviderStatus.AUTH_ERROR
        assert res.http_status_code == 401
