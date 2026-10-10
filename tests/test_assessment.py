"""Unit tests for the Risk Assessment and Prioritization Engine."""

import pytest
from soc_intel.assessment import AssessmentEngine
from soc_intel.models import (
    AssessmentConfidence,
    AssessmentPriority,
    EnrichedIndicator,
    NormalizedIndicator,
    OverallEnrichmentStatus,
    ProviderEnrichmentRecord,
)
from soc_intel.providers.base import ProviderStatus
from soc_intel.validators import IndicatorType


@pytest.fixture
def base_indicator():
    return NormalizedIndicator(
        value="198.51.100.24",
        indicator_type=IndicatorType.IPV4,
        is_public=True,
    )


@pytest.fixture
def hash_indicator():
    return NormalizedIndicator(
        value="44d88612fea8a8f36de82e1278abb02f",
        indicator_type=IndicatorType.MD5,
        is_public=True,
    )


class TestAssessmentRules:
    """Test policy prioritization, confidence calculation, and caveats."""

    def test_high_priority_multi_source_agreement(self, base_indicator):
        enriched = EnrichedIndicator(
            indicator=base_indicator,
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.SUCCESS,
                    detections=12,
                ),
                ProviderEnrichmentRecord(
                    provider_name="AbuseIPDB",
                    status=ProviderStatus.SUCCESS,
                    reputation_score=95.0,
                    detections=35,
                ),
            ],
        )

        res = AssessmentEngine.evaluate(enriched)
        assert res.priority == AssessmentPriority.HIGH
        assert res.confidence == AssessmentConfidence.HIGH
        assert "Multi-source convergence" in res.reasons[0]
        assert "Escalate" in res.recommended_action

    def test_high_priority_file_hash(self, hash_indicator):
        enriched = EnrichedIndicator(
            indicator=hash_indicator,
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.SUCCESS,
                    detections=25,
                )
            ],
        )

        res = AssessmentEngine.evaluate(enriched)
        assert res.priority == AssessmentPriority.HIGH
        assert "VirusTotal identified 25" in res.reasons[0]

    def test_medium_priority_low_detections(self, base_indicator):
        enriched = EnrichedIndicator(
            indicator=base_indicator,
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.SUCCESS,
                    detections=1,
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
        assert res.priority == AssessmentPriority.MEDIUM
        assert "VirusTotal detected suspicious" in res.reasons[0]

    def test_low_priority_with_safe_caveat(self, base_indicator):
        enriched = EnrichedIndicator(
            indicator=base_indicator,
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
        assert "Zero findings does not prove the indicator is safe" in res.caveats[0]

    def test_partial_intelligence_caveat_on_failure(self, base_indicator):
        enriched = EnrichedIndicator(
            indicator=base_indicator,
            enrichment_status=OverallEnrichmentStatus.PARTIAL,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.SUCCESS,
                    detections=0,
                ),
                ProviderEnrichmentRecord(
                    provider_name="AbuseIPDB",
                    status=ProviderStatus.TIMEOUT,
                    error_message="Gateway timeout",
                ),
            ],
        )

        res = AssessmentEngine.evaluate(enriched)
        assert res.confidence == AssessmentConfidence.LIMITED
        assert any("Partial intelligence" in caveat for caveat in res.caveats)

    def test_unconfigured_providers(self, base_indicator):
        enriched = EnrichedIndicator(
            indicator=base_indicator,
            enrichment_status=OverallEnrichmentStatus.UNCONFIGURED,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.UNCONFIGURED,
                )
            ],
        )

        res = AssessmentEngine.evaluate(enriched)
        assert res.priority == AssessmentPriority.UNDETERMINED
        assert "missing API credentials" in res.summary
