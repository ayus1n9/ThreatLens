"""Shared pytest fixtures and test configuration for ThreatLens."""

import os
import pytest
from pathlib import Path


@pytest.fixture
def temp_env_file(tmp_path: Path) -> Path:
    """Create a temporary .env file for configuration tests."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "VIRUSTOTAL_API_KEY=mock_vt_key_12345\n"
        "ABUSEIPDB_API_KEY=mock_abuse_key_67890\n"
        "ALERT_WEBHOOK_URL=https://example.com/alerts/webhook\n"
        "CACHE_ENABLED=true\n"
        "CACHE_TTL_HOURS=12\n"
        "REQUEST_TIMEOUT_SECONDS=5.0\n"
    )
    return env_file


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    """Ensure tests run isolated from the host developer's actual environment variables."""
    for key in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "ALERT_WEBHOOK_URL", "CACHE_ENABLED", "CACHE_TTL_HOURS", "REQUEST_TIMEOUT_SECONDS"]:
        monkeypatch.delenv(key, raising=False)
