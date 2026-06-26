# Cyberdebunk — Project Context

## What This Is

A security-enriched LinkedIn outbound system. The core idea: use real, public security and compliance data (CVEs, breaches, GDPR fines) to personalize cold outreach at the lead level. Lemlist handles delivery; a Python pipeline + Claude handles enrichment.

## Current Campaign State (as of 24 June 2026)

- **Campaign:** Security Outbound V1 (`cam_D4cKonCgWRYoNiEDR`)
- **Status:** Draft — 0 messages sent
- **Leads:** 23 leads across 20 unique companies
- **Pipeline runs completed:** 1 session (18 June 2026)
- **Blockers resolved:** 3 of 4 high-priority blockers have workarounds in place
- **Remaining hard blocker:** Campaign not yet activated (no outreach sent)

## Architecture

1. **ICP Sourcing** — Find leads via AI prompt, import to Lemlist campaign
2. **Security Intel Pipeline** — Per-company data pull via Python script (`pipeline.py`)
3. **Enrichment Injection** — Findings pushed into Lemlist as custom variables
4. **Sequence (manual in Lemlist UI)** — 4-step LinkedIn sequence using enriched templates
5. **Monitoring** — Weekly stats pull via agent, manual copy iteration

## Pipeline State

| Component | Status |
|---|---|
| Lemlist lead read | Fully operational |
| Domain resolution (from work email) | Fully operational |
| VirusTotal tech stack hints | Active — key configured, 500 req/day |
| SSL Labs grade + cert expiry | Active — cached lookup, no key required |
| Whois domain age + registrar | Active — system CLI |
| NVD CVE lookup | Operational — rate-limited without API key |
| HIBP breach lookup | Disabled — key not configured |
| Lemlist write-back (custom variables) | Operational |
| Censys port/service scanning | Unavailable — free API removed June 2026 |
| Shodan live scanning | Unavailable — requires $69/mo paid key |

## Data Sources

| Type | Sources |
|---|---|
| CVE / vulnerability | NVD (nvd.nist.gov) — primary. VirusTotal passive HTTP headers for tech stack narrowing |
| SSL / cert intel | SSL Labs (ssllabs.com) — cached grade + cert expiry, no key required |
| Domain intel | Whois CLI — domain age, registrar |
| Compliance / breach | HIBP API (key not configured), GDPR registries |
| Live scanning | Censys free API removed June 2026. Shodan $69/mo — not active |

## Lemlist Custom Variables (injected per lead)

`{{cvss_score}}`, `{{key_risk}}`, `{{exposed_ports}}`, `{{top_cve}}`, `{{key_cve}}`, `{{exposed_service}}`, `{{ssl_grade}}`, `{{domain_age}}`, `{{breach_date}}`, `{{compliance_flag}}`

Each enrichment entry also carries a `data_source` field (`live_scan` vs `inferred`) so downstream users know which findings are verified vs knowledge-based.

## Known Challenges & Current Solutions

### HIGH — Campaign in Draft, 0 messages sent
- **Impact:** All security intel gathered is unused until campaign is activated
- **Action:** Activate in Lemlist UI (assign sender → activate), then run `python pipeline.py --writeback`

### HIGH — CVEs matched to generic tech defaults (inferred mode)
- **Impact:** NVD results are real CVEs but not company-specific — matched to Apache/nginx/IIS defaults when VirusTotal returns no signal
- **Solution:** VirusTotal key is now configured (June 24). Passive HTTP headers give real `Server:`/`X-Powered-By:` per domain → next run will use actual tech stack for most leads
- **Remaining gap:** No live port scanning. Shodan paid ($69/mo) gives version-accurate banners for CPE-based CVE lookups

### MEDIUM — NVD rate limit without API key
- **Impact:** 5 req/30s cap → ~7 min runtime for 23 leads
- **Solution:** Auto-detects `NVD_API_KEY` and adjusts sleep. Get free key at nvd.nist.gov → add `NVD_API_KEY` to `.env` → cuts runtime to ~40sec

### MEDIUM — No breach data
- **Impact:** `breach_date` and `compliance_flag` always empty — GDPR angle unavailable
- **Action:** HIBP API key (~$4/mo at haveibeenpwned.com/API/Key) → add `HIBP_API_KEY` to `.env`

### RESOLVED — Domain resolution
- ✓ Domains extracted from work email (e.g. `erikjan@bureauveritas.com` → `bureauveritas.com`). EU TLDs resolve correctly.

### RESOLVED — Censys free API
- ✓ Removed from pipeline. Free programmatic access ended June 2026. Pipeline runs in inferred mode; VirusTotal covers the tech stack gap.

### LOW — No automated re-run trigger
- **Solution path:** GitHub Actions weekly cron + JSON diff alert on new Critical/High CVEs → Lemlist write-back

## Message Angle Logic

| Lead tag | Message angle |
|---|---|
| `has_cve` | Reference specific CVE + CVSS score + exposed service |
| `has_breach` | Reference breach date + GDPR enforcement climate |
| `no_findings` | Generic ICP-pain message or deprioritize |

## Key Constraints

- Lemlist sequence config is done **manually in the UI** — pipeline is enrichment only, not sequence automation (MVP phase)
- Claude synthesis is **knowledge-based fallback** when live scan fails — label findings accordingly
- AI-generated copy using CVE data needs **human review** before going live
- Lemlist API exposes campaign-level stats but not A/B test results in structured form

## Prioritized Next Steps

| Priority | Action | Effort |
|---|---|---|
| **Now** | Activate campaign in Lemlist UI → run `python pipeline.py --writeback` | 15 min |
| **Now** | Get free NVD API key (nvd.nist.gov) → add `NVD_API_KEY` to `.env` | 5 min |
| **Soon** | HIBP API key (~$4/mo) → unlocks breach angle for GDPR outreach | 10 min |
| **Soon** | ZoomEye free tier — fingerprinting alternative to Shodan | 30 min |
| **Later** | Shodan paid ($69/mo) — live port scanning, version-accurate CVE matching | — |
| **Later** | GitHub Actions weekly cron — auto re-run + diff alert on new Critical/High CVEs | 2 hrs |

## MVP Thresholds (before expanding)

- Connection acceptance ≥ 30%
- Step 3 reply rate ≥ 5%
- Security intel returning usable findings for ≥ 60% of leads
- No LinkedIn account warnings
- ≥ 3 replies referencing the CVE/compliance angle

## Post-MVP Roadmap

- MCP automation for sequence updates (once angles are validated)
- BuiltWith API for tech stack detection → better CVE targeting
- Lead scoring model: high CVSS + recent breach + regulated industry = priority
- Evaluate replacing Lemlist with a lighter delivery layer at volume
- Wappalyzer fingerprints for version-accurate CPE-based CVE lookups
- GitHub Actions weekly cron for pipeline re-runs + diff alerting

## Tooling

- **Python script:** `pipeline.py` — runs enrichment, supports `--writeback` flag
- **Claude Desktop + Lemlist MCP** — agent interface for sourcing, enrichment, monitoring
- **Lemlist** — campaign delivery and sequence execution
- **VirusTotal free tier** — passive HTTP headers for tech stack detection (key configured)
- **SSL Labs** — cached SSL grade + cert expiry per domain (free, no key)
- **Whois CLI** — domain age and registrar (system tool, no setup)
- **NVD REST API v2** — CVE lookup with adaptive rate limiting
- **HIBP** — domain breach lookup (key not yet configured)
- **Config:** API keys in `.env` (never commit); `.env` in `.gitignore`
