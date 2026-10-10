"""Unit tests for indicator routing, normalization, and partial-intelligence handling."""

import pytest
from soc_intel.config import Settings
from soc_intel.enrichment import EnrichmentEngine, IndicatorRouter
from soc_intel.models import OverallEnrichmentStatus
from soc_intel.providers.base import BaseProvider, ProviderRawResult, ProviderStatus
from soc_intel.validators import IndicatorType, ValidatedIndicator


class MockSuccessProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "MockSuccess"

    def supports(self, indicator_type: IndicatorType) -> bool:
        return True

    def lookup(self, indicator: ValidatedIndicator) -> ProviderRawResult:
        return ProviderRawResult(
            provider_name=self.name,
            indicator_value=indicator.normalized_value,
            indicator_type=indicator.indicator_type,
            status=ProviderStatus.SUCCESS,
            http_status_code=200,
            detections=5,
            total_evaluators=70,
            reputation_score=-10.0,
            tags=["malware"],
        )


class MockFailingProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "MockFailing"

    def supports(self, indicator_type: IndicatorType) -> bool:
        return True

    def lookup(self, indicator: ValidatedIndicator) -> ProviderRawResult:
        return ProviderRawResult(
            provider_name=self.name,
            indicator_value=indicator.normalized_value,
            indicator_type=indicator.indicator_type,
            status=ProviderStatus.TIMEOUT,
            error_message="Gateway timeout",
        )


class MockHashOnlyProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "MockHashOnly"

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256)

    def lookup(self, indicator: ValidatedIndicator) -> ProviderRawResult:
        return ProviderRawResult(
            provider_name=self.name,
            indicator_value=indicator.normalized_value,
            indicator_type=indicator.indicator_type,
            status=ProviderStatus.SUCCESS,
            detections=1,
        )


class TestRouterAndNormalization:
    """Test routing based on IOC type and evidence normalization."""

    def test_routing_ip_vs_hash(self):
        p_all = MockSuccessProvider(api_key="key")
        p_hash = MockHashOnlyProvider(api_key="key")
        router = IndicatorRouter([p_all, p_hash])

        ip_ind = ValidatedIndicator("1.1.1.1", "1.1.1.1", IndicatorType.IPV4, True)
        hash_ind = ValidatedIndicator("44d88612fea8a8f36de82e1278abb02f", "44d88612fea8a8f36de82e1278abb02f", IndicatorType.MD5, True)

        ip_providers = router.get_providers_for(ip_ind)
        assert len(ip_providers) == 1
        assert ip_providers[0].name == "MockSuccess"

        hash_providers = router.get_providers_for(hash_ind)
        assert len(hash_providers) == 2

    def test_all_providers_succeed(self):
        engine = EnrichmentEngine(
            settings=Settings(),
            providers=[MockSuccessProvider(api_key="key")]
        )
        ip_ind = ValidatedIndicator("8.8.8.8", "8.8.8.8", IndicatorType.IPV4, True)
        result = engine.enrich_indicator(ip_ind)

        assert result.enrichment_status == OverallEnrichmentStatus.COMPLETE
        assert len(result.provider_records) == 1
        assert result.provider_records[0].detections == 5
        assert result.provider_records[0].status == ProviderStatus.SUCCESS
        assert result.successful_providers == ["MockSuccess"]

    def test_partial_intelligence_when_one_provider_fails(self):
        engine = EnrichmentEngine(
            settings=Settings(),
            providers=[
                MockSuccessProvider(api_key="key"),
                MockFailingProvider(api_key="key"),
            ]
        )
        ip_ind = ValidatedIndicator("8.8.8.8", "8.8.8.8", IndicatorType.IPV4, True)
        result = engine.enrich_indicator(ip_ind)

        # Must report partial status without raising or crashing
        assert result.enrichment_status == OverallEnrichmentStatus.PARTIAL
        assert len(result.provider_records) == 2
        assert "MockSuccess" in result.successful_providers
        assert "MockFailing" in result.failed_providers

    def test_all_providers_fail(self):
        engine = EnrichmentEngine(
            settings=Settings(),
            providers=[MockFailingProvider(api_key="key")]
        )
        ip_ind = ValidatedIndicator("8.8.8.8", "8.8.8.8", IndicatorType.IPV4, True)
        result = engine.enrich_indicator(ip_ind)

        assert result.enrichment_status == OverallEnrichmentStatus.FAILED
        assert len(result.successful_providers) == 0
        assert "MockFailing" in result.failed_providers
