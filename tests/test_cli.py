"""Unit tests for the CLI commands and configuration loader."""

import pytest
from pathlib import Path
from soc_intel.cli import build_parser, main
from soc_intel.config import load_config


class TestConfigLoading:
    """Test environment configuration logic and sanitization."""

    def test_default_config_empty(self):
        cfg = load_config()
        assert cfg.has_virustotal is False
        assert cfg.has_abuseipdb is False
        assert cfg.has_webhook is False
        assert cfg.cache_enabled is True
        assert cfg.cache_ttl_hours == 24
        assert cfg.request_timeout_seconds == 10.0

    def test_config_from_env_file(self, temp_env_file: Path):
        cfg = load_config(temp_env_file)
        assert cfg.virustotal_api_key == "mock_vt_key_12345"
        assert cfg.abuseipdb_api_key == "mock_abuse_key_67890"
        assert cfg.alert_webhook_url == "https://example.com/alerts/webhook"
        assert cfg.has_virustotal is True
        assert cfg.has_abuseipdb is True
        assert cfg.has_webhook is True
        assert cfg.cache_ttl_hours == 12
        assert cfg.request_timeout_seconds == 5.0


class TestCLIOperations:
    """Test CLI parser syntax and execution."""

    def test_cli_version_flag(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "ThreatLens" in captured.out

    def test_cli_validate_single_ip(self, capsys):
        code = main(["validate", "--ip", "1.1.1.1"])
        assert code == 0
        captured = capsys.readouterr()
        assert "Validation Complete: 1 valid indicator(s)" in captured.out
        assert "[IPV4] 1.1.1.1" in captured.out

    def test_cli_validate_single_hash(self, capsys):
        code = main(["validate", "--hash", "44d88612fea8a8f36de82e1278abb02f"])
        assert code == 0
        captured = capsys.readouterr()
        assert "Validation Complete: 1 valid indicator(s)" in captured.out
        assert "[MD5] 44d88612fea8a8f36de82e1278abb02f" in captured.out

    def test_cli_enrich_day1_baseline(self, capsys):
        code = main(["enrich", "--ip", "8.8.8.8"])
        assert code == 0
        captured = capsys.readouterr()
        assert "ThreatLens Initialized (Day 1 Foundation Baseline)" in captured.out
        assert "Target Indicators: 1" in captured.out
