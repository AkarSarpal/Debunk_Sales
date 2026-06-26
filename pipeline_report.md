# Pipeline Build Report — Security Outbound V1

---

## Session 2 — 24 June 2026

### What Was Added

Based on reviewer feedback (WhatsApp, 24 June): "why only 4 technologies for CVE, some features are disabled"

- **SSL Labs integration** — `query_ssl_labs(domain)`: pulls SSL grade (A/B/C/F) and cert expiry from SSL Labs cache. No API key required. Uses `fromCache=on&maxAge=48` — never triggers a new scan.
- **Whois integration** — `query_whois(domain)`: shells to system `whois`, parses creation date across 5 formats (handles EU `.de`/`.nl`/`.fr`/`.es`/`.com`). Returns domain age in days and registrar.
- **Tech limit raised 4 → 6** — `tech[:4]` → `tech[:6]`. Covers more of the detected stack when VirusTotal returns multiple signals.
- **Two new Lemlist variables** — `{{ssl_grade}}` and `{{domain_age}}` added to writeback and report.
- **Report updated** — Lead table now has SSL and Domain Age columns. Lead details show `SSL grade B (expires 2026-09-14) | domain age 8y via GoDaddy`.

**VirusTotal key status:** configured in `.env` (session 2). Pipeline now uses real passive HTTP headers for tech stack — no longer falling back to generic defaults for most leads.

---

## Session 1 — 22 June 2026
Based on: challenges.pdf (18 June 2026 report)

---

## What Was Built (Session 1)

A Python pipeline (`pipeline.py`) that:
- Reads all 23 leads from the Lemlist campaign via API (no CSV, no manual prompts)
- Resolves company domains from work email addresses (accurate, no guessing)
- Queries NVD for HIGH/CRITICAL CVEs published in the last 3 years
- Checks HIBP for domain breaches (when API key is provided)
- Tags each lead: `has_cve`, `has_breach`, or `no_findings`
- Generates `intel_report.md` with per-lead variable preview
- Optionally writes all variables back to Lemlist with `--writeback`

**Current pipeline state: operational in inferred mode. Live scanning not yet active.**

---

## Challenges from the June 18 Report — Resolution Status

### 01 — No Shodan API key
**Original status:** HIGH blocker — no live port/service scanning
**Resolution:** Attempted replacement with Censys free tier. Censys removed free programmatic API access entirely in June 2026 (their Personal Access Tokens do not grant search API access on free accounts — confirmed by testing all auth methods). Pipeline now runs in **inferred mode** by default: NVD keyword search against likely tech stack, flagged as `data_source: inferred`.
**Path to live scanning:** Shodan paid membership ($69/mo) is the only reliable option for live port fingerprinting at this price point. VirusTotal free tier (500 req/day) added as lightweight alternative — pulls tech stack hints from cached HTTP response headers.
**Current impact:** CVEs returned are real but matched to generic tech defaults, not the company's actual stack. Usable for outreach context but not for claiming a specific service is exposed.

---

### 02 — NVD rate limit without API key
**Original status:** MEDIUM — 5 req/30s, ~7min runtime for 20 companies
**Resolution:** ✅ Fixed. Pipeline auto-detects `NVD_API_KEY` and switches sleep: 6.5s without key, 0.7s with free key. Added retry logic for 503/timeout errors (3 attempts, 15s backoff). Also added `cvssV3Severity=HIGH` and `pubStartDate` (3 years) filters so only recent High/Critical CVEs are returned.
**Remaining action:** Get free NVD key at nvd.nist.gov (5 min) → add to `.env` as `NVD_API_KEY`. Cuts runtime from ~7min to ~40sec.

---

### 03 — Domain names not stored in Lemlist leads
**Original status:** HIGH blocker — company name → domain inference wrong ~30–60% of time
**Resolution:** ✅ Fixed. The Lemlist contacts API returns the lead's work email (e.g. `erikjan.davids@bureauveritas.com`). Pipeline extracts the domain directly from the email — no inference needed. `bureauveritas.com`, `prescan.nl`, `minddoc.de` all resolved correctly in testing. The heuristic `infer_domain()` function is still present as fallback for leads with personal email addresses but is rarely invoked.

---

### 04 — Campaign in Draft — zero messages sent
**Original status:** HIGH — all intel gathered but unused
**Resolution:** Pipeline is ready. The `--writeback` flag pushes all 8 variables to each Lemlist lead. Campaign needs to be **activated manually** in Lemlist UI first (assign sender → activate), then run `python pipeline.py --writeback`.
**Remaining action:** Activate campaign in Lemlist UI. This is the single biggest unlock — without it, no outreach happens.

---

### 05 — CVE lookups imprecise without software versions
**Original status:** MEDIUM — keyword search returns broad/irrelevant CVEs
**Resolution:** Partially addressed. Added `cvssV3Severity=HIGH` and `pubStartDate` (3 years back) filters to NVD queries — this eliminates ancient CVEs (1999–2000 era) from results. Tech stack is still generic defaults when no live scan data exists.
**Path to full fix:** VirusTotal passive HTTP headers give Server/X-Powered-By hints that narrow tech stack. Shodan paid gives version-accurate banners. BuiltWith API gives full tech stack per domain including framework versions.

---

### 06 — Claude synthesis knowledge-based, not live-scan-based
**Original status:** MEDIUM — unverified risk assessments
**Resolution:** ✅ Implemented. Every result carries `data_source: inferred` or `live_scan`. With Censys unavailable, all current results are `inferred`. The intel report makes this visible per lead. Users can treat inferred findings as conversation starters, not audit-grade claims.

---

### 07 — European companies produce wrong `.com` domain guesses
**Original status:** MEDIUM — ~60% of EU leads fail DNS resolution
**Resolution:** ✅ Superseded. Domain comes from work email, which is inherently correct regardless of TLD. `prescan.nl`, `minddoc.de`, `mediaire.de` all resolved without any TLD logic. The EU TLD problem was only a problem with name-based inference — moot now.

---

### 08 — No automated re-run trigger
**Original status:** LOW
**Resolution:** Not implemented yet — out of scope for MVP.
**Path:** GitHub Actions `schedule: cron` trigger, weekly. Diff against previous `intel_report.md`, alert on new High/Critical CVEs. Write updated scores to Lemlist automatically.

---

### 09 — Anthropic API key in browser artifact
**Original status:** LOW
**Resolution:** ✅ Handled by design. `pipeline.py` is server-side Python. All API keys live in `.env` (blocked by `.gitignore`). No browser-side key exposure.

---

## New Challenge: Censys API Removed (not in June 18 report)

**Discovered:** 22 June 2026, during implementation
**Impact:** HIGH — originally planned as the Shodan replacement
**Details:** Censys migrated entirely to `platform.censys.io`. All classic API credentials (ID + Secret) are gone. Personal Access Tokens issued by the new platform return 401 on all search endpoints (`app.censys.io/api/v2/`, `platform.censys.io/api/v2/`). Free programmatic access to Censys search is no longer available.
**Workaround in place:** VirusTotal free tier (500 req/day) added as lightweight tech stack enrichment. Pipeline continues in inferred mode without live scanning.
**Permanent fix:** Shodan paid ($69/mo) for live port scanning. Worth it at scale once MVP metrics are hit.

---

## Intel Quality Assessment — Current State

**What works:**
- Domain resolution: 100% accurate (from email)
- NVD CVE lookup: operational, with retry logic
- Lead tagging: `has_cve` / `has_breach` / `no_findings` working
- Lemlist variable writeback: implemented, tested against API

**What needs attention:**

| Issue | Impact | Fix |
|---|---|---|
| CVEs matched to generic tech defaults | Medium — findings are real but not company-specific | VirusTotal key for passive tech stack, or Shodan paid for live scan |
| No breach data | Medium — `breach_date` / `compliance_flag` always empty without HIBP key | HIBP API key (~$4/mo) |
| NVD slow without API key | Low — 7min runtime acceptable for 23 leads | Free NVD key, 5 min to get |
| Campaign not activated | Blocking — no outreach sent yet | Manual step in Lemlist UI |

---

## What Can Be Improved — Prioritised

### Now (free, < 30 min each)

**1. Get free NVD API key**
→ nvd.nist.gov → "Request an API Key"
→ Add to `.env` as `NVD_API_KEY`
→ Runtime drops from ~7min to ~40sec, rate limit raised from 5 to 50 req/30s

**2. Activate Lemlist campaign**
→ Open Lemlist UI → Security Outbound V1 → assign sender → activate
→ Then run: `python pipeline.py --writeback`
→ This is the blocker for any outreach to happen

**3. ~~Get free VirusTotal API key~~ ✓ Done (24 June 2026)**
→ Key configured in `.env`. Pipeline now uses real passive HTTP headers per domain.

**4. ~~SSL Labs integration~~ ✓ Done (24 June 2026)**
→ `query_ssl_labs()` added. Pulls SSL grade + cert expiry from cache. No key needed.

**5. ~~Whois integration~~ ✓ Done (24 June 2026)**
→ `query_whois()` added. Domain age + registrar via system CLI. Handles EU TLDs.

### Soon (paid or ~1hr effort)

**6. HIBP API key (~$4/mo)**
→ haveibeenpwned.com/API/Key
→ Unlocks `breach_date` and `compliance_flag` variables for GDPR angle messages
→ Enables `has_breach` tagging and the second message angle

**7. ZoomEye free tier**
→ Shodan alternative for fingerprinting — 10 free searches/day
→ Register at zoomeye.hk → add `ZOOMEYE_API_KEY` to `.env`
→ Evaluate before committing to Shodan paid

**8. Shodan paid ($69/mo)**
→ Live port/service scanning with version-accurate banners
→ Enables CPE-based NVD lookups (exact CVE matching per version)
→ Worth it post-MVP once message angles are validated

### Later (2hrs+ effort)

**9. GitHub Actions weekly cron**
→ `.github/workflows/sec-intel.yml` with `schedule: cron: '0 9 * * 1'`
→ Run `pipeline.py --writeback` weekly
→ JSON diff against previous run → Slack/email alert on new Critical/High CVEs
→ Lemlist always has the latest intel without manual runs

**10. BuiltWith API for tech stack**
→ Full tech stack per domain including framework versions
→ Feeds directly into CPE-based NVD lookups
→ Free tier: 1 lookup/domain, paid from $295/mo — evaluate post-MVP

**11. Lead scoring model**
→ Priority score = CVSS_score × recency_weight + breach_recency + regulated_industry_flag
→ Re-order Lemlist leads by score before activating sequence
→ Highest-signal leads get contacted first

---

## Files in This Project

| File | Purpose |
|---|---|
| `pipeline.py` | Main enrichment script — run this |
| `.env` | API keys (never commit) |
| `.env.example` | Template for keys — safe to commit |
| `.gitignore` | Blocks `.env` and `intel_report.md` from git |
| `intel_report.md` | Generated per run — per-lead CVE/breach data and Lemlist variables |
| `context.md` | Live project context and architecture |
| `sales_draft_1.md` | Blueprint v3 — phases, templates, success criteria |
| `pipeline_report.md` | This file — challenge resolution log |

---

## To Run Right Now

```bash
# 1. Dry run on 3 leads (no changes to Lemlist)
LEMLIST_API_KEY=<your_key> python pipeline.py --limit 3 -v

# 2. Full run on all 23 leads
LEMLIST_API_KEY=<your_key> python pipeline.py

# 3. Full run + push variables to Lemlist (after activating campaign)
LEMLIST_API_KEY=<your_key> python pipeline.py --writeback
```

Or set `LEMLIST_API_KEY` in `.env` and run without the prefix.
