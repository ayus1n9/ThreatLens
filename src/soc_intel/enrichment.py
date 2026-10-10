"""
Enrichment Orchestration & Router Module.

Routes indicators to eligible provider clients based on IOC type (e.g., hashes only to VT,
IPs to VT + AbuseIPDB), normalizes provider findings, and applies the AssessmentEngine
to generate automated risk prioritization.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from soc_intel.assessment import AssessmentEngine
from soc_intel.config import Settings
from soc_intel.models import (
    EnrichedIndicator,
    NormalizedIndicator,
    OverallEnrichmentStatus,
    ProviderEnrichmentRecord,
)
from soc_intel.providers.abuseipdb import AbuseIPDBClient
from soc_intel.providers.base import BaseProvider, ProviderRawResult, ProviderStatus
from soc_intel.providers.virustotal import VirusTotalClient
from soc_intel.validators import ValidatedIndicator

logger = logging.getLogger("soc_intel.enrichment")


class IndicatorRouter:
    """Selects and dispatches appropriate providers based on indicator type."""

    def __init__(self, providers: List[BaseProvider]):
        self.providers = providers

    def get_providers_for(self, indicator: ValidatedIndicator) -> List[BaseProvider]:
        """Return list of providers supporting the given indicator type."""
        return [p for p in self.providers if p.supports(indicator.indicator_type)]


class EnrichmentEngine:
    """
    Coordinates threat intelligence lookups across multiple providers,
    normalizes records, aggregates partial intelligence, and evaluates risk.
    """

    def __init__(self, settings: Settings, providers: Optional[List[BaseProvider]] = None):
        self.settings = settings
        if providers is not None:
            self.providers = providers
        else:
            self.providers = [
                VirusTotalClient(
                    api_key=settings.virustotal_api_key,
                    timeout_seconds=settings.request_timeout_seconds,
                ),
                AbuseIPDBClient(
                    api_key=settings.abuseipdb_api_key,
                    timeout_seconds=settings.request_timeout_seconds,
                ),
            ]
        self.router = IndicatorRouter(self.providers)

    def normalize_provider_result(self, raw: ProviderRawResult, is_cached: bool = False) -> ProviderEnrichmentRecord:
        """Translate raw provider container to normalized Pydantic model."""
        return ProviderEnrichmentRecord(
            provider_name=raw.provider_name,
            status=raw.status,
            http_status_code=raw.http_status_code,
            query_timestamp=raw.query_timestamp,
            detections=raw.detections,
            total_evaluators=raw.total_evaluators,
            reputation_score=raw.reputation_score,
            tags=raw.tags,
            last_analysis_date=raw.last_analysis_date,
            error_message=raw.error_message,
            is_cached=is_cached,
        )

    def enrich_indicator(self, indicator: ValidatedIndicator) -> EnrichedIndicator:
        """
        Execute lookups across all eligible providers, normalize results,
        and run the assessment engine.
        """
        norm_ind = NormalizedIndicator(
            value=indicator.normalized_value,
            indicator_type=indicator.indicator_type,
            is_public=indicator.is_public,
            scope_note=indicator.scope_note,
        )

        eligible_providers = self.router.get_providers_for(indicator)

        if not eligible_providers:
            enriched_obj = EnrichedIndicator(
                indicator=norm_ind,
                enrichment_status=OverallEnrichmentStatus.SKIPPED,
                provider_records=[],
            )
            enriched_obj.assessment = AssessmentEngine.evaluate(enriched_obj)
            return enriched_obj

        provider_records: List[ProviderEnrichmentRecord] = []
        success_count = 0
        error_count = 0
        unconfigured_count = 0

        for provider in eligible_providers:
            try:
                raw_res = provider.lookup(indicator)
                rec = self.normalize_provider_result(raw_res)
                provider_records.append(rec)

                if rec.status in (ProviderStatus.SUCCESS, ProviderStatus.NOT_FOUND):
                    success_count += 1
                elif rec.status == ProviderStatus.UNCONFIGURED:
                    unconfigured_count += 1
                else:
                    error_count += 1

            except Exception as exc:
                logger.error("Unexpected error in %s lookup for %s: %s", provider.name, indicator.normalized_value, exc)
                provider_records.append(
                    ProviderEnrichmentRecord(
                        provider_name=provider.name,
                        status=ProviderStatus.ERROR,
                        error_message=f"Internal exception: {str(exc)}",
                    )
                )
                error_count += 1

        # Determine overall enrichment status
        total_eligible = len(eligible_providers)
        if unconfigured_count == total_eligible:
            overall_status = OverallEnrichmentStatus.UNCONFIGURED
        elif success_count == total_eligible:
            overall_status = OverallEnrichmentStatus.COMPLETE
        elif success_count > 0:
            overall_status = OverallEnrichmentStatus.PARTIAL
        else:
            overall_status = OverallEnrichmentStatus.FAILED

        enriched_obj = EnrichedIndicator(
            indicator=norm_ind,
            enrichment_status=overall_status,
            provider_records=provider_records,
        )

        # Run multi-factor risk assessment
        enriched_obj.assessment = AssessmentEngine.evaluate(enriched_obj)
        return enriched_obj
