"""
Configuration management for ThreatLens.

Loads and validates settings from environment variables or .env file with
strict credential sanitization and secure defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    """Application configuration and credentials."""

    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    alert_webhook_url: Optional[str] = None
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    cache_db_path: str = ".soc_intel_cache.db"
    request_timeout_seconds: float = 10.0

    @property
    def has_virustotal(self) -> bool:
        """Check if VirusTotal API key is present."""
        return bool(self.virustotal_api_key and self.virustotal_api_key.strip())

    @property
    def has_abuseipdb(self) -> bool:
        """Check if AbuseIPDB API key is present."""
        return bool(self.abuseipdb_api_key and self.abuseipdb_api_key.strip())

    @property
    def has_webhook(self) -> bool:
        """Check if Webhook URL is configured."""
        return bool(self.alert_webhook_url and self.alert_webhook_url.strip())


def load_config(env_path: Optional[Path] = None) -> Settings:
    """
    Load settings from .env file or existing environment variables.

    Args:
        env_path: Optional custom path to .env file. Defaults to current working directory or repo root.

    Returns:
        Settings: Validated dataclass instance containing settings.
    """
    if env_path and env_path.is_file():
        load_dotenv(dotenv_path=env_path)
    else:
        # Default load
        load_dotenv()

    # Parse settings with safe fallbacks
    cache_enabled_raw = os.getenv("CACHE_ENABLED", "true").lower()
    cache_enabled = cache_enabled_raw in ("true", "1", "yes")

    try:
        cache_ttl = int(os.getenv("CACHE_TTL_HOURS", "24"))
    except ValueError:
        cache_ttl = 24

    try:
        req_timeout = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "10.0"))
    except ValueError:
        req_timeout = 10.0

    return Settings(
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
        alert_webhook_url=os.getenv("ALERT_WEBHOOK_URL") or None,
        cache_enabled=cache_enabled,
        cache_ttl_hours=cache_ttl,
        cache_db_path=os.getenv("CACHE_DB_PATH", ".soc_intel_cache.db"),
        request_timeout_seconds=req_timeout,
    )
