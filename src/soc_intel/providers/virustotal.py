"""
VirusTotal v3 API Client.

Implements indicator lookups for IPv4, IPv6, MD5, SHA-1, and SHA-256 hashes
using VirusTotal REST API v3.
Docs: https://docs.virustotal.com/reference/overview
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

logger = logging.getLogger("soc_intel.providers.virustotal")


class VirusTotalClient(BaseProvider):
    """Client for VirusTotal API v3."""

    DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: Optional[str],
        timeout_seconds: float = 10.0,
        base_url: Optional[str] = None,
    ) -> None:
        super().__init__(
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            base_url=base_url or self.DEFAULT_BASE_URL,
        )

    @property
    def name(self) -> str:
        return "VirusTotal"

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in (
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.MD5,
            IndicatorType.SHA1,
            IndicatorType.SHA256,
        )

    def _parse_response_payload(
        self, data: Any, indicator: ValidatedIndicator
    ) -> ProviderRawResult:
        """
        Strictly validate the schema of VirusTotal v3 responses.
        Fails if data is malformed or attributes are not a dictionary.
        """
        if not isinstance(data, dict) or "data" not in data or not isinstance(data["data"], dict):
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=200,
                error_message="VirusTotal response schema invalid: missing top-level 'data' object.",
            )

        vt_data = data["data"]
        attributes = vt_data.get("attributes")
        if not isinstance(attributes, dict):
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=200,
                error_message="VirusTotal response schema invalid: missing or non-dict 'attributes' object.",
            )

        # Validate last_analysis_stats
        stats = attributes.get("last_analysis_stats")
        if not isinstance(stats, dict):
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=200,
                error_message="VirusTotal response schema invalid: missing or non-dict 'last_analysis_stats'.",
            )

        try:
            malicious_count = int(stats.get("malicious", 0))
            suspicious_count = int(stats.get("suspicious", 0))
            total_engines = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
            reputation = float(attributes.get("reputation", 0))
        except (ValueError, TypeError) as conv_err:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=200,
                error_message=f"VirusTotal metrics contain unexpected non-numeric types: {conv_err}",
            )

        tags_raw = attributes.get("tags", [])
        tags = [str(t) for t in tags_raw] if isinstance(tags_raw, list) else []

        last_date_epoch = attributes.get("last_analysis_date")
        last_date_str = None
        if isinstance(last_date_epoch, (int, float)):
            from datetime import datetime, timezone
            last_date_str = datetime.fromtimestamp(last_date_epoch, tz=timezone.utc).isoformat()

        return ProviderRawResult(
            provider_name=self.name,
            indicator_value=indicator.normalized_value,
            indicator_type=indicator.indicator_type,
            status=ProviderStatus.SUCCESS,
            http_status_code=200,
            raw_data=data,
            detections=malicious_count + suspicious_count,
            total_evaluators=total_engines,
            reputation_score=reputation,
            tags=tags,
            last_analysis_date=last_date_str,
        )

    def lookup(self, indicator: ValidatedIndicator) -> ProviderRawResult:
        """Query VirusTotal API v3 for an IP address or file hash."""
        if not self.supports(indicator.indicator_type):
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.UNSUPPORTED,
                error_message=f"VirusTotal does not support indicator type '{indicator.indicator_type.value}'",
            )

        if not self.api_key:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.UNCONFIGURED,
                error_message="VirusTotal API key is not configured (missing VIRUSTOTAL_API_KEY).",
            )

        if indicator.indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
            endpoint = f"{self.base_url}/ip_addresses/{indicator.normalized_value}"
        else:
            endpoint = f"{self.base_url}/files/{indicator.normalized_value}"

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatLens-SOC-Enrichment/0.1.0",
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.get(endpoint, headers=headers)
        except httpx.TimeoutException:
            logger.warning("VirusTotal request timed out for indicator: %s", indicator.normalized_value)
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.TIMEOUT,
                error_message=f"Request timed out after {self.timeout_seconds}s connecting to VirusTotal.",
            )
        except httpx.TransportError as transport_err:
            logger.error("VirusTotal transport error for %s: %s", indicator.normalized_value, transport_err)
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                error_message=f"Transport error contacting VirusTotal: {transport_err}",
            )
        except Exception as unhandled_err:
            logger.error("Unexpected error contacting VirusTotal for %s: %s", indicator.normalized_value, unhandled_err)
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
                    error_message=f"Malformed JSON returned by VirusTotal: {json_err}",
                )
            return self._parse_response_payload(data, indicator)

        elif response.status_code == 404:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.NOT_FOUND,
                http_status_code=404,
                error_message="Indicator not found in VirusTotal dataset (unseen or unindexed).",
            )

        elif response.status_code in (401, 403):
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.AUTH_ERROR,
                http_status_code=response.status_code,
                error_message=f"Authentication failed (HTTP {response.status_code}). Check VIRUSTOTAL_API_KEY.",
            )

        elif response.status_code == 429:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.RATE_LIMITED,
                http_status_code=429,
                error_message="VirusTotal API rate limit / quota exceeded (HTTP 429).",
            )

        else:
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                http_status_code=response.status_code,
                error_message=f"Unexpected HTTP {response.status_code} response from VirusTotal.",
            )
