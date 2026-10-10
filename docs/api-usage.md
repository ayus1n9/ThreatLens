# ThreatLens API Usage & Responsible Consumption

ThreatLens connects to external threat intelligence providers and adheres to strict operational safety and quota preservation standards.

---

## 1. Supported Providers

### VirusTotal REST API v3
- **Endpoints Used**:
  - IP Addresses: `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`
  - File Hashes: `GET https://www.virustotal.com/api/v3/files/{hash}`
- **Authentication**: `x-apikey: <VIRUSTOTAL_API_KEY>` header.
- **Quota Considerations**:
  - Free Community Tier: 4 requests per minute, 500 requests per day.
  - ThreatLens processes indicators sequentially and relies on local caching to avoid exhausting limits.

### AbuseIPDB REST API v2
- **Endpoint Used**:
  - `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose`
- **Authentication**: `Key: <ABUSEIPDB_API_KEY>` header.
- **Quota Considerations**:
  - Free Webmaster Tier: 1,000 checks per day.
  - Indicator restriction: AbuseIPDB accepts IP addresses only. ThreatLens router automatically excludes file hashes from querying AbuseIPDB.

---

## 2. Handling Quotas and Rate Limits (HTTP 429)

When an upstream provider returns HTTP 429 (Too Many Requests):
1. The error is isolated to that specific provider's query for that indicator.
2. The indicator status is logged as `rate_limited` with an explanatory note.
3. The remaining providers are still evaluated, allowing ThreatLens to produce a `partial` intelligence assessment.
4. **Rate limits are never cached**, ensuring that when quotas reset, lookups resume normally.
