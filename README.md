# ThreatLens: SOC Threat Intelligence and IOC Enrichment Automation

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Testing](https://img.shields.io/badge/tests-pytest-green.svg)](https://docs.pytest.org/)

**ThreatLens** is a modular, evidence-based security automation tool engineered to streamline the triage of suspicious Indicators of Compromise (IOCs)—including IPv4, IPv6, and cryptographic file hashes (MD5, SHA-1, SHA-256).

By combining and normalizing intelligence from **VirusTotal** and **AbuseIPDB**, ThreatLens removes the manual repetition from indicator enrichment while avoiding the common pitfall of blindly trusting single numerical reputation scores.

---

## Key Design Principles

1. **Evidence-Based Prioritization**: Indicators are evaluated using transparent multi-source evidence, confidence weighting, and recency indicators rather than arbitrary black-box verdicts.
2. **Resilience & Partial Intelligence**: A failure or rate-limit from one provider does not cause an entire batch run to fail. Unreachable providers are recorded as `unavailable`, and assessments are made with explicit notes regarding limited visibility.
3. **Internal Network Defense**: Private (RFC 1918), loopback, link-local, multicast, and documentation IP addresses are rejected by default before external queries are made, preventing internal infrastructure leakage.
4. **Offline Testability**: 100% of unit and integration test suites run offline with zero dependency on live API keys or external network connectivity.

---

## Project Structure

```
ThreatLens/
├── .env.example              <- Template for environment variables and secrets
├── pyproject.toml            <- Package metadata and build definitions
├── requirements.txt          <- Runtime and development dependencies
├── src/
│   └── soc_intel/
│       ├── __init__.py
│       ├── __main__.py       <- Module execution entrypoint (`python -m soc_intel`)
│       ├── cli.py            <- CLI subcommands, flags, and help formatting
│       ├── config.py         <- Secure environment configuration loader
│       ├── validators.py     <- IP address scoping & hash format validation
│       └── providers/        <- API client integrations (VirusTotal, AbuseIPDB)
├── tests/
│   ├── conftest.py           <- Test fixtures and mock isolation
│   ├── test_validators.py    <- Test suites for IOC classification & scoping
│   └── test_cli.py           <- Test suites for CLI argument parsing & config
└── samples/
    ├── indicators.txt        <- Sample newline-delimited indicators
    └── indicators.json       <- Sample structured JSON indicator array
```

---

## Installation & Setup

### 1. Clone Repository & Setup Virtual Environment
```bash
git clone https://github.com/ayus1n9/ThreatLens.git
cd ThreatLens
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure Credentials
Copy the example environment file and configure your API keys:
```bash
cp .env.example .env
```
Edit `.env`:
```ini
VIRUSTOTAL_API_KEY=your_actual_virustotal_key
ABUSEIPDB_API_KEY=your_actual_abuseipdb_key
ALERT_WEBHOOK_URL= # (Optional)
```
> **Security Notice**: `.env` is ignored by Git in `.gitignore`. Never commit API keys or production secrets to source control.

---

## Usage

### Validate Indicators (Zero API Usage)
Sanitize, classify, and audit IOCs locally:
```bash
# Validate single IP (rejects private addresses by default)
soc-intel validate --ip 8.8.8.8

# Validate single cryptographic hash
soc-intel validate --hash 44d88612fea8a8f36de82e1278abb02f

# Validate and deduplicate batch list from file
soc-intel validate --input samples/indicators.txt
```

### Execute Unit Test Suite
```bash
pytest -v
```

---

## Implementation Roadmap

- [x] **Day 1: Project Foundation** - Architecture, package setup, strict validation engine, configuration manager, CLI baseline, and unit test suite.
- [ ] **Day 2: Provider Integration** - VirusTotal v3 and AbuseIPDB v2 API clients with rate-limit and error handling.
- [ ] **Day 3: Normalized Intelligence** - Unified IOC data model, partial intelligence tolerance, and router.
- [ ] **Day 4: Assessment Engine** - Multi-source scoring, confidence evaluation, and transparent triage rationale.
- [ ] **Day 5: Batch Engine & Reporting** - JSON/CSV export, local caching with TTL, and batch executive summary.
- [ ] **Day 6: Alerts & Security Tests** - Slack/Discord webhooks with dry-run mode and security hardening.
- [ ] **Day 7: Documentation & Release** - Portfolio demonstration, comprehensive evidence, and v1.0.0 release.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
