"""
Reporting & Export Module.

Generates structured JSON and human-readable/tabular CSV reports for SOC analysts,
along with terminal executive summaries for batch workflows.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from soc_intel.models import (
    AssessmentPriority,
    EnrichedIndicator,
    OverallEnrichmentStatus,
)


@dataclass
class BatchExecutionSummary:
    """Summary metrics of a batch enrichment execution."""
    total_submitted: int
    enriched_complete: int
    enriched_partial: int
    enriched_failed: int
    skipped_or_unconfigured: int
    high_priority_count: int
    medium_priority_count: int
    low_priority_count: int
    undetermined_count: int


def calculate_batch_summary(results: List[EnrichedIndicator]) -> BatchExecutionSummary:
    """Compute aggregate triage and execution counts across a list of indicators."""
    total = len(results)
    complete = sum(1 for r in results if r.enrichment_status == OverallEnrichmentStatus.COMPLETE)
    partial = sum(1 for r in results if r.enrichment_status == OverallEnrichmentStatus.PARTIAL)
    failed = sum(1 for r in results if r.enrichment_status == OverallEnrichmentStatus.FAILED)
    skipped = sum(1 for r in results if r.enrichment_status in (OverallEnrichmentStatus.SKIPPED, OverallEnrichmentStatus.UNCONFIGURED))

    high = sum(1 for r in results if r.assessment.priority == AssessmentPriority.HIGH)
    med = sum(1 for r in results if r.assessment.priority == AssessmentPriority.MEDIUM)
    low = sum(1 for r in results if r.assessment.priority == AssessmentPriority.LOW)
    undetermined = sum(1 for r in results if r.assessment.priority == AssessmentPriority.UNDETERMINED)

    return BatchExecutionSummary(
        total_submitted=total,
        enriched_complete=complete,
        enriched_partial=partial,
        enriched_failed=failed,
        skipped_or_unconfigured=skipped,
        high_priority_count=high,
        medium_priority_count=med,
        low_priority_count=low,
        undetermined_count=undetermined,
    )


class ReportGenerator:
    """Renders structured JSON, CSV, or formatted terminal outputs."""

    @staticmethod
    def to_json(results: List[EnrichedIndicator], output_path: Optional[Path] = None, indent: int = 2) -> str:
        """Serialize enrichment results to standard JSON."""
        data = [r.model_dump() for r in results]
        json_str = json.dumps(data, indent=indent)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_str, encoding="utf-8")
        return json_str

    @staticmethod
    def to_csv(results: List[EnrichedIndicator], output_path: Optional[Path] = None) -> str:
        """
        Export enrichment results into a standardized CSV table for SOC triage.
        Fields: Indicator, Type, Provider Status, Threat Priority, Evidence Summary,
                Source Coverage, Lookup Time, Recommended Action.
        """
        import io
        output = io.StringIO()
        fieldnames = [
            "Indicator",
            "Type",
            "Provider Status",
            "Threat Priority",
            "Evidence Summary",
            "Source Coverage",
            "Lookup Time",
            "Recommended Action",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for res in results:
            coverage = f"{len(res.successful_providers)}/{len(res.provider_records)} providers"
            row = {
                "Indicator": res.indicator.value,
                "Type": res.indicator.indicator_type.value.upper(),
                "Provider Status": res.enrichment_status.value.capitalize(),
                "Threat Priority": res.assessment.priority.value.upper(),
                "Evidence Summary": res.assessment.summary,
                "Source Coverage": coverage,
                "Lookup Time": res.enrichment_timestamp,
                "Recommended Action": res.assessment.recommended_action,
            }
            writer.writerow(row)

        csv_str = output.getvalue()
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(csv_str, encoding="utf-8")
        return csv_str

    @staticmethod
    def format_terminal_summary(results: List[EnrichedIndicator]) -> str:
        """Produce a formatted executive summary string for terminal output."""
        summary = calculate_batch_summary(results)
        lines = [
            "\n" + "=" * 65,
            "             THREATLENS SOC TRIAGE BATCH SUMMARY",
            "=" * 65,
            f" Total Indicators Submitted  : {summary.total_submitted}",
            f" Complete Enrichment         : {summary.enriched_complete}",
            f" Partial Enrichment          : {summary.enriched_partial}",
            f" Failed Lookups              : {summary.enriched_failed}",
            f" Skipped / Unconfigured      : {summary.skipped_or_unconfigured}",
            "-" * 65,
            " Triage Prioritization Breakdown:",
            f"   [!] HIGH Priority         : {summary.high_priority_count}  (Immediate containment recommended)",
            f"   [*] MEDIUM Priority       : {summary.medium_priority_count}  (Contextual investigation required)",
            f"   [-] LOW Priority          : {summary.low_priority_count}  (No active findings reported)",
            f"   [?] UNDETERMINED          : {summary.undetermined_count}  (Inconclusive / insufficient visibility)",
            "=" * 65,
        ]
        return "\n".join(lines)
