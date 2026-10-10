"""
Normalized data models for ThreatLens.

Defines the unified internal schema for indicators, provider execution statuses,
evidence points, and final triage assessments.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from soc_intel.providers.base import ProviderStatus
from soc_intel.validators import IndicatorType


class OverallEnrichmentStatus(str, Enum):
    """Overall status of multi-provider enrichment for an indicator."""
    COMPLETE = "complete"      # All eligible configured providers succeeded
    PARTIAL = "partial"        # At least one provider succeeded, but one or more failed/timed out
    FAILED = "failed"          # All queried providers failed or encountered errors
    UNCONFIGURED = "unconfigured"  # No eligible provider has configured credentials
    SKIPPED = "skipped"        # Indicator was not queried (e.g. internal IP)


class ProviderEnrichmentRecord(BaseModel):
    """Normalized evidence record from a single threat intelligence provider."""
    provider_name: str
    status: ProviderStatus
    http_status_code: Optional[int] = None
    query_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    detections: int = 0
    total_evaluators: int = 0
    reputation_score: Optional[float] = None
    tags: List[str] = Field(default_factory=list)
    last_analysis_date: Optional[str] = None
    error_message: Optional[str] = None
    is_cached: bool = False


class NormalizedIndicator(BaseModel):
    """Sanitized identity of the indicator under investigation."""
    value: str
    indicator_type: IndicatorType
    is_public: bool = True
    scope_note: Optional[str] = None


class AssessmentPriority(str, Enum):
    """Prioritization verdict for SOC analyst workflow."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNDETERMINED = "undetermined"


class AssessmentConfidence(str, Enum):
    """Confidence level in the assessment based on available evidence and coverage."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    LIMITED = "limited"


class AssessmentResult(BaseModel):
    """Synthesized risk triage assessment produced by the assessment engine."""
    priority: AssessmentPriority = AssessmentPriority.UNDETERMINED
    confidence: AssessmentConfidence = AssessmentConfidence.LIMITED
    summary: str = "Awaiting assessment."
    reasons: List[str] = Field(default_factory=list)
    recommended_action: str = "Review indicator context within network logs."
    caveats: List[str] = Field(default_factory=list)


class EnrichedIndicator(BaseModel):
    """
    Complete audit-ready representation of an indicator, including raw provider
    findings, normalized summary, and risk prioritization.
    """
    indicator: NormalizedIndicator
    enrichment_status: OverallEnrichmentStatus
    provider_records: List[ProviderEnrichmentRecord] = Field(default_factory=list)
    assessment: AssessmentResult = Field(default_factory=AssessmentResult)
    enrichment_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def successful_providers(self) -> List[str]:
        return [r.provider_name for r in self.provider_records if r.status == ProviderStatus.SUCCESS]

    @property
    def failed_providers(self) -> List[str]:
        return [
            r.provider_name for r in self.provider_records
            if r.status in (ProviderStatus.ERROR, ProviderStatus.TIMEOUT, ProviderStatus.RATE_LIMITED, ProviderStatus.AUTH_ERROR)
        ]
