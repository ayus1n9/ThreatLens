# ThreatLens: SOC Threat Intelligence and IOC Enrichment Automation

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Testing](https://img.shields.io/badge/tests-87%20passed-brightgreen.svg)](https://docs.pytest.org/)
[![Security](https://img.shields.io/badge/zero--leakage-RFC1918--protected-blueviolet.svg)](docs/security.md)

**ThreatLens** is an automated threat intelligence enrichment tool built in Python. It ingests suspicious Indicators of Compromise (IOCs)—including IPv4, IPv6, and cryptographic file hashes (MD5, SHA-1, SHA-256)—enriches them using **VirusTotal** and **AbuseIPDB**, normalizes multi-source evidence, and generates transparent, audit-ready triage assessments for Security Operations Center (SOC) analysts.

---

## What Will Impress a SOC Hiring Manager?

1. **Evidence-Based Prioritization, Not Blind Faith**:
   Rather than treating a single external reputation score as a universal verdict, ThreatLens applies multi-source consensus, evaluation thresholds, and recency analysis.
2. **"Absence of Evidence Is Not Evidence of Safety"**:
   When an indicator returns zero detections, ThreatLens explicitly warns analysts that clean scores do not prove benign intent—avoiding false sense of security for novel or targeted threats.
3. **Internal Topology Leak Prevention**:
   Strict pre-flight validation automatically blocks RFC 1918, loopback, link-local, and documentation IP addresses from being queried against public external threat intelligence providers.
4. **Resilience to Partial Outages**:
   If an external provider suffers an outage (HTTP 500), rate limit (HTTP 429), or timeout, ThreatLens gracefully degrades to a `partial` status with explicit visibility notes instead of failing the batch.
5. **100% Offline Testability**:
   The entire 60-test automated test suite executes fully offline without requiring real API keys or internet connectivity.

---

## System Architecture

```
                            Analyst Request (CLI / File / JSON)
                                           │
                                           ▼
                               ┌───────────────────────┐
                               │   Input Validation    │
                               │  - IPv4 / IPv6 Syntax │
                               │  - Public vs Private  │
                               │  - MD5 / SHA1 / SHA256│
                               │  - Deduplication      │
                               └───────────┬───────────┘
                                           │
                                           ▼
                               ┌───────────────────────┐
                               │   Indicator Router    │
                               │  - IP: VT + AbuseIPDB │
                               │  - Hashes: VT only    │
                               └───────────┬───────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        │ Consult SQLite Cache                │
                        │ (TTL check, bypass if --no-cache)   │
                        └──────────────────┬──────────────────┘
                                           │
                       ┌───────────────────┴───────────────────┐
                       ▼                                       ▼
            ┌──────────────────────┐               ┌──────────────────────┐
            │   VirusTotal v3 API  │               │   AbuseIPDB v2 API   │
            │  - IP / File Hashes  │               │  - IP Addresses Only │
            │  - Engine Detections │               │  - Abuse Reports/ISP │
            └──────────┬───────────┘               └──────────┬───────────┘
                       └───────────────────┬───────────────────┘
                                           │
                                           ▼
                               ┌───────────────────────┐
                               │   Result Normalizer   │
                               │  - Unified Schema     │
                               │  - Status Tracking    │
                               │  - Error Resiliency   │
                               └───────────┬───────────┘
                                           │
                                           ▼
                               ┌───────────────────────┐
                               │   Assessment Engine   │
                               │  - High/Med/Low/Undet │
                               │  - Multi-source Rules │
                               │  - Explicit Caveats   │
                               └───────────┬───────────┘
                                           │
                 ┌─────────────────────────┴─────────────────────────┐
                 ▼                                                   ▼
     ┌───────────────────────┐                           ┌───────────────────────┐
     │  Reports & Summaries  │                           │  Optional Webhook     │
     │  - Terminal Executive │                           │  - Slack / Discord    │
     │  - CSV Tabular Matrix │                           │  - Dry-Run Inspection │
     │  - JSON Structured Log│                           └───────────────────────┘
     └───────────────────────┘
```

---

## Directory Structure

```
ThreatLens/
├── README.md                      <- Main project portfolio documentation
├── LICENSE                        <- MIT License
├── .gitignore                     <- Ignores .env, .venv, *.db, cache, reports
├── .env.example                   <- Template for API keys and webhook secrets
├── pyproject.toml                 <- Package configuration & build entrypoints
├── requirements.txt               <- Pinned runtime & testing dependencies
├── src/
│   └── soc_intel/
│       ├── __init__.py
│       ├── __main__.py            <- CLI launcher (`python -m soc_intel`)
│       ├── cli.py                 <- CLI argument parser & subcommand routing
│       ├── config.py              <- Environment & secrets configuration
│       ├── validators.py          <- IP classification (RFC 1918) & hash verification
│       ├── models.py              <- Pydantic normalized data models
│       ├── enrichment.py          <- Router, orchestrator, and batch processing
│       ├── assessment.py          <- Multi-source risk assessment engine
│       ├── cache.py               <- SQLite persistent cache with TTL
│       ├── reporting.py           <- JSON, CSV, and terminal report generators
│       ├── notifications.py       <- Slack/Discord webhook alerting & dry-run
│       └── providers/
│           ├── __init__.py
│           ├── base.py            <- BaseProvider ABC and status definitions
│           ├── virustotal.py      <- VirusTotal v3 API Client
│           └── abuseipdb.py       <- AbuseIPDB v2 API Client
├── tests/
│   ├── conftest.py                <- Isolated test fixtures
│   ├── test_validators.py         <- IOC classification & scoping tests (17 tests)
│   ├── test_providers.py          <- VirusTotal & AbuseIPDB mocked API tests (12 tests)
│   ├── test_enrichment.py         <- Indicator routing & partial intelligence tests (4 tests)
│   ├── test_assessment.py         <- Policy prioritization & caveats tests (6 tests)
│   ├── test_cache.py              <- SQLite cache & TTL tests (5 tests)
│   ├── test_reporting.py          <- JSON & CSV export tests (4 tests)
│   ├── test_notifications.py      <- Webhook formatting & network tests (5 tests)
│   └── test_cli.py                <- CLI interface & argument parsing tests (7 tests)
├── samples/
│   ├── indicators.txt             <- Sample batch input (IPs & Hashes)
│   └── indicators.json            <- Sample JSON batch input
├── docs/
│   ├── architecture.md            <- Detailed subsystem architecture
│   ├── risk-assessment.md         <- Decision logic matrix & scoring policy
│   ├── api-usage.md               <- API quota management & endpoint references
│   └── security.md                <- Defensive safeguards & secrets handling
├── reports/                       <- Generated output reports (JSON/CSV)
└── evidence/
    ├── README.md                  <- Traceability matrix & execution artifacts
    └── generate_mock_evidence.py  <- Artifact generation script
```

---

## Quick Start & Installation

### 1. Clone & Set Up Virtual Environment
```bash
git clone https://github.com/ayus1n9/ThreatLens.git
cd ThreatLens
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure Environment Keys
```bash
cp .env.example .env
```
Populate `.env` with your API credentials:
```ini
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
ALERT_WEBHOOK_URL=https://example.com/alerts/webhook  # Optional
```
> **Security Note**: `.env` is excluded by `.gitignore` and never committed to version control.

---

## CLI Usage Guide

### 1. Validate Indicators Locally (Zero API Consumption)
Sanitize indicators, detect private IPs, and verify hash lengths:
```bash
# Validate single IP address
soc-intel validate --ip 8.8.8.8

# Validate cryptographic file hash
soc-intel validate --hash 44d88612fea8a8f36de82e1278abb02f

# Validate & deduplicate batch file
soc-intel validate --input samples/indicators.txt
```

### 2. Enrich Single Indicators
```bash
# Enrich public IP
soc-intel enrich --ip 1.1.1.1

# Enrich file hash (automatically routed solely to VirusTotal)
soc-intel enrich --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 3. Batch Processing & Report Generation
```bash
# Export structured JSON report
soc-intel enrich --input samples/indicators.txt --format json --output reports/triage_report.json

# Export SOC triage CSV table
soc-intel enrich --input samples/indicators.txt --format csv --output reports/triage_report.csv
```

### 4. Cache Management
```bash
# Force fresh lookups bypassing local SQLite cache
soc-intel enrich --ip 8.8.8.8 --no-cache
```

### 5. Webhook Alerts & Dry-Run Mode
```bash
# Dry-run inspection (renders webhook alert locally without transmitting)
soc-intel enrich --input samples/indicators.txt --notify --webhook-dry-run
```

---

## Automated Test Suite

ThreatLens features a comprehensive test suite covering all functional, edge-case, and failure scenarios using `pytest` and `respx`.

```bash
pytest -v
```

**Output**:
```text
============================== 60 passed in 0.26s ==============================
```

---

## Documentation Links

- [System Architecture](docs/architecture.md)
- [Risk Assessment Policy & Decision Matrix](docs/risk-assessment.md)
- [API Quotas & Provider Usage](docs/api-usage.md)
- [Security & Defensive Safeguards](docs/security.md)
- [Evidence & Test Traceability Matrix](evidence/README.md)

---

## License

This project is licensed under the [MIT License](LICENSE).
