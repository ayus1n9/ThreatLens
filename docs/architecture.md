# ThreatLens Architecture & Design Overview

ThreatLens is an automated threat intelligence enrichment tool designed to assist SOC analysts in triaging Indicators of Compromise (IOCs) rapidly and objectively.

---

## 1. High-Level System Architecture

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

## 2. Component Directory & Responsibilities

| Subsystem | Module | Role & Responsibility |
|---|---|---|
| **CLI & Dispatch** | `soc_intel.cli` | Argument parsing, flags (`--ip`, `--hash`, `--input`, `--format`, `--output`, `--no-cache`, `--notify`, `--webhook-dry-run`), and human-friendly terminal tables. |
| **Configuration** | `soc_intel.config` | Securely reads environment variables and `.env` files into a frozen `Settings` object with safe timeouts and fallbacks. |
| **IOC Validation** | `soc_intel.validators` | Strict RFC 1918 / RFC 5737 private and documentation IP filtering to prevent accidental leak of internal enterprise networks; strict length and hex checks for MD5, SHA-1, and SHA-256 hashes. |
| **Providers** | `soc_intel.providers.*` | Handles REST API interaction, HTTP headers, authentication, status code handling (401, 404, 429), timeouts, and JSON parsing. |
| **Cache Engine** | `soc_intel.cache` | SQLite persistent store (`.soc_intel_cache.db`) indexing findings with configurable TTLs. Prevents redundant API consumption. |
| **Normalizer** | `soc_intel.models` & `soc_intel.enrichment` | Translates varied provider schemas into a unified Pydantic model (`EnrichedIndicator`) while tracking coverage and partial failures. |
| **Assessment** | `soc_intel.assessment` | Rule-based engine calculating priority, confidence, containment actions, and human-readable reasoning strings. |
| **Reporting** | `soc_intel.reporting` | JSON and CSV serialization, tabular summaries, and batch execution metrics. |
| **Notifications** | `soc_intel.notifications` | Slack and Discord incoming webhook alerting with dry-run inspection mode and payload size capping. |
