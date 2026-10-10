"""
AbuseIPDB v2 API Client.

Implements indicator reputation and abuse-report enrichment for IPv4 and IPv6 addresses.
Docs: https://docs.abuseipdb.com/#check-endpoint
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import json

import httpx

from soc_intel.providers.base import (
    BaseProvider,
    ProviderRawResult,
    ProviderStatus,
)
from soc_intel.validators import IndicatorType, ValidatedIndicator

logger = logging.getLogger("soc_intel.providers.abuseipdb")


class AbuseIPDBClient(BaseProvider):
    """Client for AbuseIPDB API v2."""

    DEFAULT_BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(
        self,
        api_key: Optional[str],
        timeout_seconds: float = 10.0,
        base_url: Optional[str] = None,
        max_age_in_days: int = 90,
    ) -> None:
        super().__init__(
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            base_url=base_url or self.DEFAULT_BASE_URL,
        )
        self.max_age_in_days = max_age_in_days

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6)

    def _parse_response_payload(
        self, data: Any, indicator: ValidatedIndicator
    ) -> ProviderRawResult:
        """Strictly validate the schema of AbuseIPDB responses."""
        if not isinstance(data, dict) or "data" not in data or not isinstance(data["data"], dict):
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=200,
                error_message="AbuseIPDB response schema invalid: missing top-level 'data' object.",
            )

        report_data = data["data"]
        if "abuseConfidenceScore" not in report_data:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=200,
                error_message="AbuseIPDB response schema invalid: missing 'abuseConfidenceScore'.",
            )

        try:
            abuse_score = float(report_data["abuseConfidenceScore"])
            total_reports = int(report_data.get("totalReports", 0))
            num_distinct_users = int(report_data.get("numDistinctUsers", 0))
        except (ValueError, TypeError) as conv_err:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=200,
                error_message=f"AbuseIPDB numerical values have unexpected types: {conv_err}",
            )

        last_reported_at = report_data.get("lastReportedAt")
        last_reported_str = str(last_reported_at) if last_reported_at else None

        country_code = report_data.get("countryCode")
        usage_type = report_data.get("usageType")
        isp = report_data.get("isp")

        tags: List[str] = []
        if usage_type:
            tags.append(f"Usage: {usage_type}")
        if isp:
            tags.append(f"ISP: {isp}")
        if country_code:
            tags.append(f"Geo: {country_code}")

        return ProviderRawResult(
            provider_name=self.name,
            indicator_value=indicator.normalized_value,
            indicator_type=indicator.indicator_type,
            status=ProviderStatus.SUCCESS,
            http_status_code=200,
            raw_data=data,
            detections=total_reports,
            total_evaluators=num_distinct_users,
            reputation_score=abuse_score,
            tags=tags,
            last_analysis_date=last_reported_str,
        )

    def lookup(self, indicator: ValidatedIndicator) -> ProviderRawResult:
        """Query AbuseIPDB API v2 for IP reputation and abuse history."""
        if not self.supports(indicator.indicator_type):
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.UNSUPPORTED,
                error_message="AbuseIPDB does not support file hashes or non-IP indicators.",
            )

        if not self.api_key:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.UNCONFIGURED,
                error_message="AbuseIPDB API key is not configured (missing ABUSEIPDB_API_KEY).",
            )

        endpoint = f"{self.base_url}/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatLens-SOC-Enrichment/0.1.0",
        }
        params = {
            "ipAddress": indicator.normalized_value,
            "maxAgeInDays": str(self.max_age_in_days),
            "verbose": "",
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.get(endpoint, headers=headers, params=params)
        except httpx.TimeoutException:
            logger.warning("AbuseIPDB request timed out for indicator: %s", indicator.normalized_value)
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.TIMEOUT,
                error_message=f"Request timed out after {self.timeout_seconds}s connecting to AbuseIPDB.",
            )
        except httpx.TransportError as transport_err:
            logger.error("AbuseIPDB transport error for %s: %s", indicator.normalized_value, transport_err)
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                error_message=f"Transport error contacting AbuseIPDB: {transport_err}",
            )
        except Exception as unhandled_err:
            logger.error("Unexpected error contacting AbuseIPDB for %s: %s", indicator.normalized_value, unhandled_err)
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                error_message=f"Unexpected client exception: {unhandled_err}",
            )

        if response.status_code == 200:
            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError) as json_err:
                return ProviderRawResult(
                    provider_name=self.name,
                    indicator_value=indicator.normalized_value,
                    indicator_type=indicator.indicator_type,
                    status=ProviderStatus.ERROR,
                    http_status_code=200,
                    error_message=f"Malformed JSON returned by AbuseIPDB: {json_err}",
                )
            return self._parse_response_payload(data, indicator)

        elif response.status_code in (401, 403):
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.AUTH_ERROR,
                http_status_code=response.status_code,
                error_message=f"Authentication failed (HTTP {response.status_code}). Check ABUSEIPDB_API_KEY.",
            )

        elif response.status_code == 429:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.RATE_LIMITED,
                http_status_code=429,
                error_message="AbuseIPDB API rate limit exceeded (HTTP 429).",
            )

        elif response.status_code == 404:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.NOT_FOUND,
                http_status_code=404,
                error_message="Indicator not found or invalid in AbuseIPDB.",
            )

        else:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=response.status_code,
                error_message=f"Unexpected HTTP {response.status_code} response from AbuseIPDB.",
            )
