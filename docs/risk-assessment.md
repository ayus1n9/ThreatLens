# ThreatLens Risk Assessment & Prioritization Policy

ThreatLens implements transparent, evidence-based prioritization for Indicators of Compromise (IOCs). Rather than trusting individual reputation scores blindly, it evaluates multiple corroborating dimensions to determine triage urgency for SOC analysts.

---

## 1. Prioritization Verdicts

| Verdict | Meaning | Actionable SOC Guidance |
|---|---|---|
| **High** | Multi-source agreement or high vendor consensus indicating verified malicious activity. | **Escalate for active containment**. Block indicator at perimeter controls (firewall/proxy/EDR) and perform retro-hunting across SIEM. |
| **Medium** | Suspicious activity observed or moderate abuse reports requiring contextual correlation. | **Investigate context**. Query internal proxy/DNS logs; verify whether IP belongs to dynamic cloud/CDN infrastructure. |
| **Low** | No active malicious findings reported across queried providers at lookup time. | **Standard logging**. No immediate containment warranted unless corroborated by internal host alerts. |
| **Undetermined** | Inconclusive intelligence due to provider failures, timeouts, or missing API credentials. | **Manual triage**. Check provider quotas/credentials; analyze raw indicator metadata or submit sample to isolated sandbox. |

---

## 2. Decision Logic Matrix

### High Priority Conditions
An indicator receives **High Priority** if any of the following apply:
1. **Multi-Source Consensus**: VirusTotal detections $\ge 3$ **and** AbuseIPDB confidence score $\ge 50\%$.
2. **High-Confidence File Hash**: VirusTotal security vendor detections $\ge 5$ (hashes query VirusTotal exclusively).
3. **Severe Abuse IP History**: AbuseIPDB score $\ge 80\%$ corroborated by $\ge 10$ distinct abuse reports.
4. **Severe Vendor Consensus**: VirusTotal detection count $\ge 7$.

### Medium Priority Conditions
An indicator receives **Medium Priority** if:
- VirusTotal reports between $1$ and $6$ detections, **or**
- AbuseIPDB reports confidence score between $20\%$ and $79\%$ with at least $2$ abuse reports.

### Low Priority Conditions
- VirusTotal reports $0$ detections **and** AbuseIPDB reports score $< 20\%$.

---

## 3. Explicit SOC Caveats & Limitations

1. **Absence of Evidence is Not Evidence of Safety**:
   If an indicator has 0 detections on VirusTotal or AbuseIPDB, ThreatLens **never** declares the indicator "safe". It notes that no findings were returned by the queried providers. Zero-day threats, highly targeted malware, and newly provisioned C2 infrastructure frequently bypass public blocklists initially.
2. **Shared Cloud & Fast-Flux Infrastructure**:
   IP addresses belonging to major cloud providers (AWS, Azure, Cloudflare) may have past abuse reports while currently serving benign workloads, or vice-versa. ThreatLens captures ISP and Usage tags to inform analyst discernment.
3. **Partial Intelligence**:
   When an upstream provider times out or throttles requests (HTTP 429), ThreatLens flags the assessment with a **Limited** confidence level and explicitly records which providers were unreachable.
