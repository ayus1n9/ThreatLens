"""
Risk Assessment and Prioritization Engine.

Implements transparent, evidence-based threat triage without blind faith in single scores.
Explicitly tracks provider coverage, distinguishes genuine zero-detection results
from NOT_FOUND (unindexed) or missing/failed provider data, and separates operational
execution status from analytical threat confidence.
"""

from __future__ import annotations

from typing import List, Optional

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
        Evaluate normalized findings and produce an objective, evidence-based assessment.
        """
        reasons: List[str] = []
        caveats: List[str] = []

        # 1. Segment provider records by execution and intelligence availability
        success_with_data = [r for r in enriched.provider_records if r.status == ProviderStatus.SUCCESS]
        not_found_records = [r for r in enriched.provider_records if r.status == ProviderStatus.NOT_FOUND]
        unconfigured_records = [r for r in enriched.provider_records if r.status == ProviderStatus.UNCONFIGURED]
        failed_records = [
            r for r in enriched.provider_records
            if r.status in (ProviderStatus.ERROR, ProviderStatus.TIMEOUT, ProviderStatus.RATE_LIMITED, ProviderStatus.AUTH_ERROR)
        ]

        total_eligible = len(enriched.provider_records)

        # Edge case: No external credentials configured
        if enriched.enrichment_status == OverallEnrichmentStatus.UNCONFIGURED or (unconfigured_records and len(unconfigured_records) == total_eligible):
            return AssessmentResult(
                priority=AssessmentPriority.UNDETERMINED,
                confidence=AssessmentConfidence.LIMITED,
                summary="Assessment unavailable due to missing API credentials.",
                reasons=["No external threat intelligence providers were configured with valid API keys."],
                recommended_action="Configure VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY in environment or .env.",
                caveats=["Zero external intelligence visibility."],
            )

        # Edge case: All queried providers failed (transport errors, timeouts, rate limits)
        if failed_records and len(failed_records) == total_eligible:
            fail_notes = [f"{r.provider_name}: {r.error_message or r.status.value}" for r in failed_records]
            return AssessmentResult(
                priority=AssessmentPriority.UNDETERMINED,
                confidence=AssessmentConfidence.LIMITED,
                summary="Enrichment failed across queried providers.",
                reasons=[f"Provider lookup failures encountered: {'; '.join(fail_notes)}"],
                recommended_action="Check network connectivity, API keys, or provider quotas before retrying.",
                caveats=["Assessment cannot be performed without provider intelligence."],
            )

        # Edge case: Both/all providers returned NOT_FOUND (Definitive lookup, but zero index history)
        if not_found_records and len(not_found_records) == total_eligible:
            return AssessmentResult(
                priority=AssessmentPriority.UNDETERMINED,
                confidence=AssessmentConfidence.LIMITED,
                summary="Undetermined: Indicator is unknown / unindexed across queried providers.",
                reasons=[
                    f"Lookup succeeded across all providers ({', '.join(r.provider_name for r in not_found_records)}), "
                    "but the indicator has no historical telemetry or indexed records."
                ],
                recommended_action="Treat indicator as novel. Perform internal host forensics or sandbox detonation.",
                caveats=[
                    "An unindexed (404 Not Found) indicator is NOT clean or benign. Targeted or newly provisioned infrastructure frequently lacks public indexing."
                ],
            )

        # Document coverage limitations
        if failed_records:
            caveats.append(
                f"Partial intelligence: {len(failed_records)} provider(s) failed ({', '.join(r.provider_name for r in failed_records)}). "
                "Assessment is derived strictly from surviving providers; missing data was NOT treated as zero detections."
            )

        if unconfigured_records:
            caveats.append(
                f"Unconfigured providers: {', '.join(r.provider_name for r in unconfigured_records)} was not queried."
            )

        if not_found_records:
            caveats.append(
                f"Unindexed: {', '.join(r.provider_name for r in not_found_records)} has no record for this indicator."
            )

        # Extract findings specifically from providers that returned definitive intelligence
        vt_record = next((r for r in success_with_data if r.provider_name == "VirusTotal"), None)
        abuse_record = next((r for r in success_with_data if r.provider_name == "AbuseIPDB"), None)

        # Explicitly distinguish None (missing/failed/unindexed) from genuine numeric 0 detections
        vt_detections: Optional[int] = vt_record.detections if vt_record else None
        abuse_score: Optional[float] = abuse_record.reputation_score if (abuse_record and abuse_record.reputation_score is not None) else None
        abuse_reports: Optional[int] = abuse_record.detections if abuse_record else None

        # --- EVALUATE TRIAGE POLICY ---
        # 1. HIGH PRIORITY RULES
        # Multi-source convergence
        if vt_detections is not None and vt_detections >= 3 and abuse_score is not None and abuse_score >= 50.0:
            priority = AssessmentPriority.HIGH
            confidence = AssessmentConfidence.HIGH
            summary = "High priority: Corroborated malicious activity detected across multiple sources."
            reasons.append(
                f"Multi-source convergence: VirusTotal reported {vt_detections} engine detections "
                f"and AbuseIPDB reported confidence score of {abuse_score:.0f}% ({abuse_reports} reports)."
            )
            recommended_action = "Escalate for active containment. Block indicator at perimeter firewall/EDR and search SIEM for internal connections."

        # High-confidence File Hash
        elif enriched.indicator.indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256) and vt_detections is not None and vt_detections >= 5:
            priority = AssessmentPriority.HIGH
            confidence = AssessmentConfidence.MEDIUM if failed_records or unconfigured_records else AssessmentConfidence.HIGH
            summary = "High priority: Corroborated malicious activity detected for file hash."
            reasons.append(
                f"High engine detection threshold: VirusTotal identified {vt_detections} security vendor detections for file hash."
            )
            recommended_action = "Escalate for active containment. Quarantine endpoint and isolate infected file."

        # Severe AbuseIPDB history
        elif abuse_score is not None and abuse_score >= 80.0 and abuse_reports is not None and abuse_reports >= 10:
            priority = AssessmentPriority.HIGH
            confidence = AssessmentConfidence.MEDIUM if (vt_record is None) else AssessmentConfidence.HIGH
            summary = "High priority: Corroborated severe abuse activity."
            reasons.append(
                f"AbuseIPDB reported severe confidence score of {abuse_score:.0f}% across {abuse_reports} distinct abuse reports."
            )
            recommended_action = "Escalate for active containment. Block indicator at perimeter firewall."

        # Severe VirusTotal detection count
        elif vt_detections is not None and vt_detections >= 7:
            priority = AssessmentPriority.HIGH
            confidence = AssessmentConfidence.MEDIUM if (abuse_record is None) else AssessmentConfidence.HIGH
            summary = "High priority: Severe security vendor consensus."
            reasons.append(
                f"VirusTotal reported severe vendor detection count ({vt_detections} security vendors flagged as malicious/suspicious)."
            )
            recommended_action = "Escalate for active containment. Block indicator at perimeter firewall/EDR."

        # 2. MEDIUM PRIORITY RULES
        elif (vt_detections is not None and vt_detections >= 1) or (abuse_score is not None and abuse_score >= 20.0 and (abuse_reports or 0) >= 2):
            priority = AssessmentPriority.MEDIUM
            confidence = AssessmentConfidence.HIGH if (vt_record and abuse_record) else AssessmentConfidence.MEDIUM
            summary = "Medium priority: Suspicious activity observed requiring analyst context."
            if vt_detections is not None and vt_detections >= 1:
                reasons.append(f"VirusTotal detected suspicious/malicious activity ({vt_detections} engine(s)).")
            if abuse_score is not None and abuse_score >= 20.0:
                reasons.append(f"AbuseIPDB recorded moderate abuse confidence of {abuse_score:.0f}% ({abuse_reports} report(s)).")
            recommended_action = "Review internal telemetry for historical connections; verify if associated with legitimate shared/cloud hosting."

        # 3. LOW PRIORITY RULES (CRITICAL FIX: Only assigned if ALL queried providers returned GENUINE low/zero results without missing/failed data)
        elif (vt_detections is not None and vt_detections == 0) and (abuse_score is not None and abuse_score < 20.0) and not failed_records and not unconfigured_records:
            priority = AssessmentPriority.LOW
            confidence = AssessmentConfidence.HIGH
            summary = "Low priority: No active malicious findings recorded across full provider suite."
            reasons.append(
                f"Both VirusTotal (0 detections) and AbuseIPDB ({abuse_score:.0f}% score) actively reported no current malicious activity."
            )
            recommended_action = "Standard monitoring. No immediate containment needed unless corroborated by internal host alerts."
            caveats.append(
                "Zero findings does not prove the indicator is safe; threats may be novel, targeted, or unindexed."
            )

        # File hash low priority (hashes only query VT)
        elif enriched.indicator.indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256) and vt_detections == 0 and not failed_records and not unconfigured_records:
            priority = AssessmentPriority.LOW
            confidence = AssessmentConfidence.MEDIUM
            summary = "Low priority: Zero vendor detections recorded for file hash."
            reasons.append("VirusTotal security engines reported 0 detections for this hash at time of query.")
            recommended_action = "Standard monitoring. Confirm hash integrity against known golden images."
            caveats.append(
                "Zero detections does not prove the file is safe; custom or packed malware often evades static hash lookups."
            )

        # 4. UNDETERMINED / PARTIAL INTELLIGENCE RULE
        else:
            # If we reached here with partial intelligence (e.g. VT timed out, AbuseIPDB had 0; or one was NOT_FOUND)
            priority = AssessmentPriority.UNDETERMINED
            confidence = AssessmentConfidence.LIMITED
            summary = "Undetermined: Inconclusive findings or incomplete provider visibility."

            obs = []
            if vt_detections is not None:
                obs.append(f"VirusTotal: {vt_detections} detections")
            elif any(r.provider_name == "VirusTotal" and r.status == ProviderStatus.NOT_FOUND for r in not_found_records):
                obs.append("VirusTotal: unindexed (404)")
            elif any(r.provider_name == "VirusTotal" for r in failed_records):
                obs.append("VirusTotal: failed/timed out")

            if abuse_score is not None:
                obs.append(f"AbuseIPDB: {abuse_score:.0f}% score")
            elif any(r.provider_name == "AbuseIPDB" and r.status == ProviderStatus.NOT_FOUND for r in not_found_records):
                obs.append("AbuseIPDB: unindexed (404)")
            elif any(r.provider_name == "AbuseIPDB" for r in failed_records):
                obs.append("AbuseIPDB: failed/timed out")

            reasons.append(f"Available provider observations: {'; '.join(obs) if obs else 'None'}. Insufficient corroboration for a definitive low or high verdict.")
            recommended_action = "Analyze network connection context manually and retry incomplete lookups when upstream providers are reachable."

        return AssessmentResult(
            priority=priority,
            confidence=confidence,
            summary=summary,
            reasons=reasons,
            recommended_action=recommended_action,
            caveats=caveats,
        )
