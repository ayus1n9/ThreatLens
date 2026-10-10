"""
VirusTotal v3 API Client.

Implements indicator lookups for IPv4, IPv6, MD5, SHA-1, and SHA-256 hashes
using VirusTotal REST API v3.
Docs: https://docs.virustotal.com/reference/overview
"""

from __future__ import annotations

import logging
from typing import Optional

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
        # VirusTotal v3 supports IPs and Hashes
        return indicator_type in (
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.MD5,
            IndicatorType.SHA1,
            IndicatorType.SHA256,
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

        # Build endpoint according to indicator type
        if indicator.indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
            endpoint = f"{self.base_url}/ip_addresses/{indicator.normalized_value}"
        else:
            # File hash (MD5, SHA1, SHA256)
            endpoint = f"{self.base_url}/files/{indicator.normalized_value}"

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatLens-SOC-Enrichment/0.1.0",
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.get(endpoint, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious_count = int(stats.get("malicious", 0))
                suspicious_count = int(stats.get("suspicious", 0))
                total_engines = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
                reputation = float(attributes.get("reputation", 0))
                tags = list(attributes.get("tags", []))

                # VirusTotal epoch timestamp
                last_date_epoch = attributes.get("last_analysis_date")
                last_date_str = None
                if last_date_epoch:
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

        except httpx.TimeoutException:
            logger.warning("VirusTotal request timed out for indicator: %s", indicator.normalized_value)
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.TIMEOUT,
                error_message=f"Request timed out after {self.timeout_seconds}s connecting to VirusTotal.",
            )

        except (httpx.RequestError, Exception) as exc:
            logger.error("VirusTotal communication error for %s: %s", indicator.normalized_value, str(exc))
            return ProviderRawResult(
                provider_name=self.name,
                indicator_value=indicator.normalized_value,
                indicator_type=indicator.indicator_type,
                status=ProviderStatus.ERROR,
                error_message=f"Network error contacting VirusTotal: {str(exc)}",
            )
