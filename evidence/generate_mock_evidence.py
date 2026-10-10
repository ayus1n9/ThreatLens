"""Generate mock enriched demonstration report for evidence documentation."""

from pathlib import Path
from soc_intel.models import (
    AssessmentConfidence,
    AssessmentPriority,
    AssessmentResult,
    EnrichedIndicator,
    NormalizedIndicator,
    OverallEnrichmentStatus,
    ProviderEnrichmentRecord,
)
from soc_intel.providers.base import ProviderStatus
from soc_intel.reporting import ReportGenerator
from soc_intel.validators import IndicatorType

mock_results = [
    EnrichedIndicator(
        indicator=NormalizedIndicator(
            value="198.51.100.23",
            indicator_type=IndicatorType.IPV4,
            is_public=True,
            scope_note="Public routable address",
        ),
        enrichment_status=OverallEnrichmentStatus.COMPLETE,
        provider_records=[
            ProviderEnrichmentRecord(
                provider_name="VirusTotal",
                status=ProviderStatus.SUCCESS,
                http_status_code=200,
                detections=14,
                total_evaluators=88,
                reputation_score=-40.0,
                tags=["c2", "cobalt-strike"],
                last_analysis_date="2026-10-10T08:00:00+00:00",
            ),
            ProviderEnrichmentRecord(
                provider_name="AbuseIPDB",
                status=ProviderStatus.SUCCESS,
                http_status_code=200,
                detections=58,
                total_evaluators=22,
                reputation_score=100.0,
                tags=["Usage: Data Center/Web Hosting", "ISP: EvilHost Corp", "Geo: RU"],
                last_analysis_date="2026-10-10T06:30:00+00:00",
            ),
        ],
        assessment=AssessmentResult(
            priority=AssessmentPriority.HIGH,
            confidence=AssessmentConfidence.HIGH,
            summary="High priority: Corroborated malicious activity detected.",
            reasons=[
                "Multi-source convergence: VirusTotal reported 14 engine detections and AbuseIPDB reported confidence score of 100% (58 reports)."
            ],
            recommended_action="Escalate for active containment. Block indicator at perimeter firewall/EDR and search SIEM for internal connections.",
            caveats=[],
        ),
    ),
    EnrichedIndicator(
        indicator=NormalizedIndicator(
            value="44d88612fea8a8f36de82e1278abb02f",
            indicator_type=IndicatorType.MD5,
            is_public=True,
            scope_note="Cryptographic file hash",
        ),
        enrichment_status=OverallEnrichmentStatus.COMPLETE,
        provider_records=[
            ProviderEnrichmentRecord(
                provider_name="VirusTotal",
                status=ProviderStatus.SUCCESS,
                http_status_code=200,
                detections=52,
                total_evaluators=71,
                reputation_score=-90.0,
                tags=["trojan", "ransomware", "lockbit"],
                last_analysis_date="2026-10-09T14:22:00+00:00",
            )
        ],
        assessment=AssessmentResult(
            priority=AssessmentPriority.HIGH,
            confidence=AssessmentConfidence.MEDIUM,
            summary="High priority: Corroborated malicious activity detected.",
            reasons=[
                "High engine detection threshold: VirusTotal identified 52 security vendor detections for file hash."
            ],
            recommended_action="Escalate for active containment. Quarantine endpoint and isolate infected file.",
            caveats=[],
        ),
    ),
    EnrichedIndicator(
        indicator=NormalizedIndicator(
            value="1.1.1.1",
            indicator_type=IndicatorType.IPV4,
            is_public=True,
            scope_note="Public routable address",
        ),
        enrichment_status=OverallEnrichmentStatus.COMPLETE,
        provider_records=[
            ProviderEnrichmentRecord(
                provider_name="VirusTotal",
                status=ProviderStatus.SUCCESS,
                http_status_code=200,
                detections=0,
                total_evaluators=92,
                reputation_score=150.0,
                tags=["dns", "cloudflare"],
            ),
            ProviderEnrichmentRecord(
                provider_name="AbuseIPDB",
                status=ProviderStatus.SUCCESS,
                http_status_code=200,
                detections=0,
                total_evaluators=0,
                reputation_score=0.0,
                tags=["Usage: Content Delivery Network (CDN)", "ISP: Cloudflare, Inc."],
            ),
        ],
        assessment=AssessmentResult(
            priority=AssessmentPriority.LOW,
            confidence=AssessmentConfidence.HIGH,
            summary="Low priority: No significant malicious findings recorded by available providers.",
            reasons=[
                "No active malicious detections reported by available providers at the time of lookup (VT detections: 0, AbuseIPDB score: 0%)."
            ],
            recommended_action="Standard monitoring. No immediate containment needed unless corroborated by internal host alerts.",
            caveats=[
                "Zero findings does not prove the indicator is safe; threats may be novel, targeted, or unindexed."
            ],
        ),
    ),
]

reports_dir = Path("reports")
ReportGenerator.to_json(mock_results, output_path=reports_dir / "sample_enriched_report.json")
ReportGenerator.to_csv(mock_results, output_path=reports_dir / "sample_enriched_report.csv")
print("[+] Generated sample enriched reports in reports/")
