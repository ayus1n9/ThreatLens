# ThreatLens Security Architecture & Defensive Controls

ThreatLens is engineered with defensiveness and responsible threat intelligence usage at its core.

---

## 1. Zero Internal Network Leakage
Querying an external threat intelligence service (e.g. VirusTotal or AbuseIPDB) with an internal, non-routable IP address leaks internal network topologies and server addresses to public third parties.

ThreatLens enforces pre-flight address validation:
- Detects and rejects:
  - RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Loopback (`127.0.0.0/8`, `::1`)
  - Link-Local (`169.254.0.0/16`, `fe80::/10`)
  - Documentation Networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- Requires explicit analyst override (`--allow-private-ips`) for intentional internal correlations.

---

## 2. Secrets Management & Zero Credential Exposure
- API Keys (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) and Webhook URLs (`ALERT_WEBHOOK_URL`) are read from process environment variables or `.env`.
- `.env` is ignored by Git via `.gitignore`.
- HTTP client headers and diagnostic logs strictly redact authorization tokens.
- Exceptions raised during network errors sanitize parameters to prevent printing authorization keys in terminal traces.

---

## 3. Webhook Delivery & Secret Protection
- Webhook endpoints accept triage summaries and high-level indicator metadata only.
- Raw API payloads containing potential proprietary logs are stripped before transmission.
- `--webhook-dry-run` allows local verification of the exact JSON payload before sending to communication channels.

---

## 4. Cache Integrity & Non-Benign Failures
- The local SQLite cache records successful and not-found responses.
- Network timeouts, HTTP 429 rate limits, and 5xx upstream outages are **never** stored in the cache.
- Prevents transient failures from masquerading as definitive benign findings.
