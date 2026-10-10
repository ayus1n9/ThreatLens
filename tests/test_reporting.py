"""Unit tests for JSON and CSV report generators and batch summaries."""

import json
from pathlib import Path
from soc_intel.models import (
    AssessmentPriority,
    AssessmentResult,
    EnrichedIndicator,
    NormalizedIndicator,
    OverallEnrichmentStatus,
    ProviderEnrichmentRecord,
)
from soc_intel.providers.base import ProviderStatus
from soc_intel.reporting import ReportGenerator, calculate_batch_summary
from soc_intel.validators import IndicatorType


def sample_enriched_list():
    return [
        EnrichedIndicator(
            indicator=NormalizedIndicator(
                value="1.1.1.1",
                indicator_type=IndicatorType.IPV4,
            ),
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.SUCCESS,
                    detections=0,
                )
            ],
            assessment=AssessmentResult(
                priority=AssessmentPriority.LOW,
                summary="Low priority: Clean",
                recommended_action="Monitor",
            ),
        ),
        EnrichedIndicator(
            indicator=NormalizedIndicator(
                value="44d88612fea8a8f36de82e1278abb02f",
                indicator_type=IndicatorType.MD5,
            ),
            enrichment_status=OverallEnrichmentStatus.COMPLETE,
            provider_records=[
                ProviderEnrichmentRecord(
                    provider_name="VirusTotal",
                    status=ProviderStatus.SUCCESS,
                    detections=30,
                )
            ],
            assessment=AssessmentResult(
                priority=AssessmentPriority.HIGH,
                summary="High priority: Malware hash",
                recommended_action="Isolate host",
            ),
        ),
    ]


class TestReporting:
    """Test JSON, CSV serialization and summary calculations."""

    def test_calculate_batch_summary(self):
        items = sample_enriched_list()
        summary = calculate_batch_summary(items)
        assert summary.total_submitted == 2
        assert summary.enriched_complete == 2
        assert summary.high_priority_count == 1
        assert summary.low_priority_count == 1

    def test_json_generation(self, tmp_path: Path):
        items = sample_enriched_list()
        out_file = tmp_path / "report.json"
        json_str = ReportGenerator.to_json(items, output_path=out_file)
        assert out_file.exists()
        parsed = json.loads(json_str)
        assert len(parsed) == 2
        assert parsed[0]["indicator"]["value"] == "1.1.1.1"

    def test_csv_generation(self, tmp_path: Path):
        items = sample_enriched_list()
        out_file = tmp_path / "report.csv"
        csv_str = ReportGenerator.to_csv(items, output_path=out_file)
        assert out_file.exists()
        assert "Indicator,Type,Provider Status" in csv_str
        assert "1.1.1.1,IPV4,Complete,LOW" in csv_str
        assert "44d88612fea8a8f36de82e1278abb02f,MD5,Complete,HIGH" in csv_str

    def test_terminal_summary_formatting(self):
        items = sample_enriched_list()
        summary_text = ReportGenerator.format_terminal_summary(items)
        assert "THREATLENS SOC TRIAGE BATCH SUMMARY" in summary_text
        assert "HIGH Priority         : 1" in summary_text
