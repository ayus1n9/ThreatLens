"""Unit tests for SQLite local caching and TTL management."""

import pytest
import sqlite3
import time
from pathlib import Path
from soc_intel.cache import ThreatIntelCache
from soc_intel.providers.base import ProviderRawResult, ProviderStatus
from soc_intel.validators import IndicatorType


@pytest.fixture
def temp_cache(tmp_path: Path) -> ThreatIntelCache:
    db_file = tmp_path / "cache.db"
    return ThreatIntelCache(db_path=str(db_file), ttl_hours=1, enabled=True)


class TestThreatIntelCache:
    """Test local cache storage, retrieval, and TTL logic."""

    def test_cache_miss_returns_none(self, temp_cache):
        assert temp_cache.get("VirusTotal", IndicatorType.IPV4, "8.8.8.8") is None

    def test_set_and_get_success(self, temp_cache):
        res = ProviderRawResult(
            provider_name="VirusTotal",
            indicator_value="8.8.8.8",
            indicator_type=IndicatorType.IPV4,
            status=ProviderStatus.SUCCESS,
            http_status_code=200,
            detections=2,
            total_evaluators=70,
            reputation_score=-5.0,
            tags=["dns", "google"],
        )
        temp_cache.set(res)

        cached = temp_cache.get("VirusTotal", IndicatorType.IPV4, "8.8.8.8")
        assert cached is not None
        assert cached.provider_name == "VirusTotal"
        assert cached.detections == 2
        assert cached.tags == ["dns", "google"]

    def test_errors_are_never_cached(self, temp_cache):
        res = ProviderRawResult(
            provider_name="VirusTotal",
            indicator_value="8.8.8.8",
            indicator_type=IndicatorType.IPV4,
            status=ProviderStatus.TIMEOUT,
            error_message="Gateway timeout",
        )
        temp_cache.set(res)
        # Verify not cached
        assert temp_cache.get("VirusTotal", IndicatorType.IPV4, "8.8.8.8") is None

    def test_cache_expiry(self, tmp_path: Path):
        db_file = tmp_path / "cache_expired.db"
        cache = ThreatIntelCache(db_path=str(db_file), ttl_hours=0, enabled=True)
        res = ProviderRawResult(
            provider_name="AbuseIPDB",
            indicator_value="1.1.1.1",
            indicator_type=IndicatorType.IPV4,
            status=ProviderStatus.SUCCESS,
            reputation_score=0.0,
        )
        cache.set(res)
        # Because TTL is 0 hours, it is immediately considered expired
        time.sleep(0.01)
        assert cache.get("AbuseIPDB", IndicatorType.IPV4, "1.1.1.1") is None

    def test_cache_clear(self, temp_cache):
        res = ProviderRawResult(
            provider_name="AbuseIPDB",
            indicator_value="1.1.1.1",
            indicator_type=IndicatorType.IPV4,
            status=ProviderStatus.SUCCESS,
        )
        temp_cache.set(res)
        assert temp_cache.get("AbuseIPDB", IndicatorType.IPV4, "1.1.1.1") is not None
        temp_cache.clear()
        assert temp_cache.get("AbuseIPDB", IndicatorType.IPV4, "1.1.1.1") is None
