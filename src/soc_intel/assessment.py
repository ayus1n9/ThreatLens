"""
Risk Assessment and Prioritization Engine.

Implements transparent, evidence-based threat triage without blind faith in single scores.
Evaluates multi-source detections, reporter consensus, recency, coverage gaps,
and generates human-readable reasoning and actionable SOC next steps.
"""

from __future__ import annotations

from typing import List

from soc_intel.models import (
    AssessmentConfidence,
    AssessmentPriority,
    AssessmentResult,
    EnrichedIndicator,
    OverallEnrichmentStatus,
)
from soc_intel.providers.base import ProviderStatus
from soc_intel.validators import IndicatorType


class AssessmentEngine:
    """
    Evaluates normalized indicator evidence against explicit SOC triage policies.
    """

    @classmethod
    def evaluate(cls, enriched: EnrichedIndicator) -> AssessmentResult:
        """
        Evaluate normalized findings and produce an assessment result.
        """
        reasons: List[str] = []
        caveats: List[str] = []

        successful_records = [r for r in enriched.provider_records if r.status == ProviderStatus.SUCCESS]
        failed_records = [
            r for r in enriched.provider_records
            if r.status in (ProviderStatus.ERROR, ProviderStatus.TIMEOUT, ProviderStatus.RATE_LIMITED, ProviderStatus.AUTH_ERROR)
        ]
        unconfigured_records = [r for r in enriched.provider_records if r.status == ProviderStatus.UNCONFIGURED]

        # Handle edge case: unconfigured providers
        if enriched.enrichment_status == OverallEnrichmentStatus.UNCONFIGURED:
            return AssessmentResult(
                priority=AssessmentPriority.UNDETERMINED,
                confidence=AssessmentConfidence.LIMITED,
                summary="Assessment unavailable due to missing API credentials.",
                reasons=["No external threat intelligence providers were configured with valid API keys."],
                recommended_action="Configure VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY in environment or .env.",
                caveats=["Zero external intelligence visibility."],
            )

        # Handle complete failure of all providers
        if enriched.enrichment_status == OverallEnrichmentStatus.FAILED or not successful_records:
            fail_notes = [f"{r.provider_name}: {r.error_message or r.status.value}" for r in failed_records]
            return AssessmentResult(
                priority=AssessmentPriority.UNDETERMINED,
                confidence=AssessmentConfidence.LIMITED,
                summary="Enrichment failed across queried providers.",
                reasons=[f"Provider lookup failures encountered: {'; '.join(fail_notes)}"],
                recommended_action="Check network connectivity, API keys, or provider quotas before retrying.",
                caveats=["Assessment cannot be performed without provider intelligence."],
            )

        # Note partial intelligence limitations
        if failed_records:
            caveats.append(
                f"Partial intelligence: {len(failed_records)} provider(s) failed ({', '.join(r.provider_name for r in failed_records)}). "
                "Assessment is based on incomplete visibility."
            )

        if unconfigured_records:
            caveats.append(
                f"Unconfigured providers: {', '.join(r.provider_name for r in unconfigured_records)} was not queried."
            )

        # Gather signals across successful providers
        vt_record = next((r for r in successful_records if r.provider_name == "VirusTotal"), None)
        abuse_record = next((r for r in successful_records if r.provider_name == "AbuseIPDB"), None)

        vt_detections = vt_record.detections if vt_record else 0
        abuse_score = abuse_record.reputation_score if (abuse_record and abuse_record.reputation_score is not None) else 0.0
        abuse_reports = abuse_record.detections if abuse_record else 0

        # Evaluate Evidence Policy
        is_high = False
        is_medium = False
        is_low = False

        # --- HIGH PRIORITY RULES ---
        # 1. Multi-source agreement on malicious activity
        if vt_detections >= 3 and abuse_score >= 50.0:
            is_high = True
            reasons.append(
                f"Multi-source convergence: VirusTotal reported {vt_detections} engine detections "
                f"and AbuseIPDB reported confidence score of {abuse_score:.0f}% ({abuse_reports} reports)."
            )
        # 2. Strong single-source Hash detection (hashes route solely to VT)
        elif enriched.indicator.indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256) and vt_detections >= 5:
            is_high = True
            reasons.append(
                f"High engine detection threshold: VirusTotal identified {vt_detections} security vendor detections for file hash."
            )
        # 3. Severe AbuseIPDB score with corroborating volume
        elif abuse_score >= 80.0 and abuse_reports >= 10:
            is_high = True
            reasons.append(
                f"AbuseIPDB reported severe confidence score of {abuse_score:.0f}% across {abuse_reports} distinct abuse reports."
            )
        # 4. Severe VirusTotal IP detection count
        elif vt_detections >= 7:
            is_high = True
            reasons.append(
                f"VirusTotal reported severe vendor detection count ({vt_detections} security vendors flagged as malicious/suspicious)."
            )

        # --- MEDIUM PRIORITY RULES ---
        elif vt_detections >= 1 or (abuse_score >= 20.0 and abuse_reports >= 2):
            is_medium = True
            if vt_detections >= 1:
                reasons.append(f"VirusTotal detected suspicious/malicious activity ({vt_detections} engine(s)).")
            if abuse_score >= 20.0:
                reasons.append(f"AbuseIPDB recorded moderate abuse confidence of {abuse_score:.0f}% ({abuse_reports} report(s)).")

        # --- LOW PRIORITY / BENIGN RULES ---
        elif vt_detections == 0 and abuse_score < 20.0:
            is_low = True
            reasons.append(
                f"No active malicious detections reported by available providers at the time of lookup "
                f"(VT detections: 0, AbuseIPDB score: {abuse_score:.0f}%)."
            )
            caveats.append(
                "Zero findings does not prove the indicator is safe; threats may be novel, targeted, or unindexed."
            )

        # Determine Priority
        if is_high:
            priority = AssessmentPriority.HIGH
            summary = "High priority: Corroborated malicious activity detected."
            recommended_action = "Escalate for active containment. Block indicator at perimeter firewall/EDR and search SIEM for internal connections."
        elif is_medium:
            priority = AssessmentPriority.MEDIUM
            summary = "Medium priority: Suspicious activity observed requiring analyst context."
            recommended_action = "Review internal telemetry for historical connections; verify if associated with legitimate shared/cloud hosting."
        elif is_low:
            priority = AssessmentPriority.LOW
            summary = "Low priority: No significant malicious findings recorded by available providers."
            recommended_action = "Standard monitoring. No immediate containment needed unless corroborated by internal host alerts."
        else:
            priority = AssessmentPriority.UNDETERMINED
            summary = "Undetermined: Inconclusive findings."
            recommended_action = "Inspect raw provider metadata or perform sandbox detonation."

        # Determine Confidence
        if len(successful_records) >= 2 and not failed_records:
            confidence = AssessmentConfidence.HIGH
        elif len(successful_records) >= 1 and not failed_records:
            confidence = AssessmentConfidence.MEDIUM
        else:
            confidence = AssessmentConfidence.LIMITED

        return AssessmentResult(
            priority=priority,
            confidence=confidence,
            summary=summary,
            reasons=reasons,
            recommended_action=recommended_action,
            caveats=caveats,
        )
