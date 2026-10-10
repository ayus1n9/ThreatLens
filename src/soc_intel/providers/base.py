"""
Base classes, exceptions, and models for Threat Intelligence providers.

Provides a unified interface and standard error hierarchy for querying
external threat intelligence services like VirusTotal and AbuseIPDB.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from soc_intel.validators import IndicatorType, ValidatedIndicator


class ProviderStatus(str, Enum):
    """Execution status of a provider query."""
    SUCCESS = "success"
    NOT_FOUND = "not_found"
    UNCONFIGURED = "unconfigured"
    UNSUPPORTED = "unsupported"
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"
    TIMEOUT = "timeout"
    ERROR = "error"


class ProviderError(Exception):
    """Base exception for provider query failures."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class AuthenticationError(ProviderError):
    """Invalid, revoked, or missing API credentials (HTTP 401/403)."""


class RateLimitExceededError(ProviderError):
    """Provider API quota or rate-limit reached (HTTP 429)."""


class IndicatorNotFoundError(ProviderError):
    """Indicator is unknown / not indexed in provider database (HTTP 404)."""


class ProviderTimeoutError(ProviderError):
    """Network connection or read timeout during provider communication."""


@dataclass
class ProviderRawResult:
    """
    Standard container for an individual provider's raw findings.
    
    Preserves provider-specific context, errors, and metadata without
    flattening premature assumptions.
    """
    provider_name: str
    indicator_value: str
    indicator_type: IndicatorType
    status: ProviderStatus
    query_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    http_status_code: Optional[int] = None
    raw_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    # Key extracted indicators
    detections: int = 0
    total_evaluators: int = 0
    reputation_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    last_analysis_date: Optional[str] = None


class BaseProvider(ABC):
    """Abstract Base Class for all Threat Intelligence API Clients."""

    def __init__(
        self,
        api_key: Optional[str],
        timeout_seconds: float = 10.0,
        base_url: Optional[str] = None,
    ) -> None:
        self.api_key = api_key.strip() if api_key else None
        self.timeout_seconds = timeout_seconds
        self.base_url = base_url

    @property
    @abstractmethod
    def name(self) -> str:
        """Friendly identifier for the provider (e.g. 'VirusTotal')."""

    @abstractmethod
    def supports(self, indicator_type: IndicatorType) -> bool:
        """Return True if this provider supports looking up the given indicator type."""

    @abstractmethod
    def lookup(self, indicator: ValidatedIndicator) -> ProviderRawResult:
        """
        Execute lookup for the given indicator.
        
        Must return a ProviderRawResult and gracefully handle provider-level
        errors without raising uncaught network exceptions.
        """
