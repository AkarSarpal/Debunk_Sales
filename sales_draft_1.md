# Security-Enriched LinkedIn Outbound — Blueprint v3

## What Changed from v2

v2 assumed Phase 3 would be done via manual agent prompts asking Claude to query Shodan + NVD per company. v3 replaces that entirely with an automated Python script (`pipeline.py`) that runs in one command. Shodan and Censys are both unavailable as free data sources — Censys removed free programmatic API access in June 2026. NVD (CVEs) is the primary enrichment source; domain is resolved from the lead's work email rather than guessed from the company name.

---

## Core Architecture

```
ICP Sourcing (Claude Desktop + Lemlist MCP)
     ↓
pipeline.py  ←  NVD CVE lookup + HIBP breach check
             ←  VirusTotal tech hints + SSL Labs grade + Whois domain age
     ↓
--writeback  →  Lemlist custom variables per lead
     ↓
Lemlist sequence (configured manually in UI)
     ↓
Monitor replies → iterate
```

---

## Phase 1: MCP Setup

Connect Lemlist to Claude Desktop.

1. Add the Lemlist MCP server to `claude_desktop_config.json`
2. Restart Claude Desktop and authenticate via OAuth (no API keys needed)
3. Verify: *"List my active Lemlist campaigns"*

The MCP is used for lead sourcing and monitoring. Enrichment is handled by `pipeline.py` directly.

---

## Phase 2: ICP Sourcing

**Prompt:**
> "Find 50 [Job Title]s at [Industry] companies in [Geography] with [X–Y] employees. Deduplicate against my existing contacts. Create a campaign called 'Security Outbound V1' in Lemlist and import the leads."

Start at 50 leads. QA enrichment quality before scaling.

---

## Phase 3: Security Intel Pipeline

Phase 3 is now a single command. No manual prompting needed.

### Setup (one-time)

```bash
cp .env.example .env
# Fill in: LEMLIST_API_KEY (required), NVD_API_KEY (free, 5min, cuts runtime 7min → 40sec)
```

### Run

```bash
# Dry run — generates intel_report.md, no changes to Lemlist
python pipeline.py

# Push variables to Lemlist leads
python pipeline.py --writeback

# Test on 3 leads first
python pipeline.py --limit 3 -v
```

### What the pipeline does per lead

1. **Fetch from Lemlist** — reads all leads + contacts from the campaign via API
2. **Resolve domain** — uses the lead's work email domain (e.g. `erikjan@bureauveritas.com` → `bureauveritas.com`). No guessing.
3. **Tech stack** — VirusTotal passive HTTP headers give real `Server:`/`X-Powered-By:` per domain. Falls back to common web stack defaults if no signal.
4. **SSL + domain intel** — SSL Labs cached scan gives SSL grade (A–F) and cert expiry. Whois gives domain age and registrar.
5. **CVE lookup** — queries NVD for HIGH/CRITICAL CVEs in the last 3 years matching the detected tech stack (up to 6 technologies). Adaptive rate limiting: 6.5s/req without key, 0.7s with free key.
6. **Breach check** — queries HIBP for domain breaches in last 24 months (requires paid HIBP key).
7. **Tag lead** — `has_cve`, `has_breach`, or `no_findings`
8. **Write back** — with `--writeback`, patches these variables to each Lemlist lead:

| Variable | Example value |
|---|---|
| `{{cvss_score}}` | `8.8` |
| `{{key_cve}}` | `CVE-2024-38475` |
| `{{key_risk}}` | `HIGH` |
| `{{exposed_service}}` | `Apache HTTP Server` |
| `{{exposed_ports}}` | `80,443,8080` |
| `{{ssl_grade}}` | `B` |
| `{{domain_age}}` | `12y` |
| `{{breach_date}}` | `2024-03-15` |
| `{{compliance_flag}}` | `GDPR breach flagged` |

Each finding carries a `data_source` field (`live_scan` vs `inferred`) so you know which are verified.

### Data sources

| Source | What it gives | Cost | Status |
|---|---|---|---|
| NVD (nvd.nist.gov) | CVEs by tech keyword, CVSS scores | Free (key optional) | ✓ Active |
| VirusTotal | Passive tech stack hints from HTTP headers | Free (500/day) | ✓ Active — key configured |
| SSL Labs | SSL grade (A–F) + cert expiry | Free, no key | ✓ Active |
| Whois | Domain age + registrar | Free, CLI | ✓ Active |
| HIBP | Domain breach history | ~$4/mo | Optional — key not configured |
| Shodan | Live port/service scanning, version banners | $69/mo | Not used |
| Censys | Live port/service scanning | Free API removed June 2026 | Not available |

---

## Phase 4: Configure Sequence in Lemlist UI

**Do this manually — no code needed.**

Recommended 4-step structure:

- **Step 1 (Day 1):** LinkedIn Profile Visit
- **Step 2 (Day 1, +2h):** Connection Request — no note
- **Step 3 (Day 3):** Opening message (security angle)
- **Step 4 (Day 7):** Follow-up if no reply

### Message Templates

**Step 3 — CVE angle** (use when `lemlistTag = has_cve`):

> "Hey {{firstName}} — did some research on {{companyName}} before reaching out. Found an active CVE ({{key_cve}}, CVSS {{cvss_score}}) affecting {{exposed_service}} that's still showing up in public scans. Teams in [industry] are often surprised how long these stay unpatched. Worth 15 min to show you what we found?"

**Step 3 — Breach angle** (use when `lemlistTag = has_breach`):

> "Hey {{firstName}} — {{companyName}} showed up in a breach dataset from {{breach_date}}. Given how actively GDPR enforcement is moving right now, a lot of [industry] teams are quietly auditing their exposure. Thought this might be timely."

**Step 3 — Generic fallback** (use when `lemlistTag = no_findings`):

> "Hey {{firstName}} — we work with a lot of [industry] teams on reducing their external attack surface before it becomes an incident. Would it make sense to show you what we typically find in a 20-minute scan?"

**Step 4 — Follow-up:**

> "Didn't want this to get lost, {{firstName}}. If the timing's off, just say the word — otherwise I'm happy to share the full report."

### Fallback tag logic

Set these in Lemlist before activating the sequence:
- `has_cve` — CVE-angle message (pipeline sets this automatically via `--writeback`)
- `has_breach` — compliance-angle message
- `no_findings` — generic ICP pain or deprioritize

---

## Phase 5: Monitor and Iterate

### Weekly stats pull (via Claude Desktop + Lemlist MCP):
> "Pull stats for 'Security Outbound V1': connection acceptance rate, Step 3 reply rate, Step 4 reply rate. Flag anything below: acceptance < 30%, Step 3 reply < 5%."

### If reply rate < 5%:
> "Rewrite the Step 3 message for `has_cve` leads — make the opening more specific to what we found, less generic. Show me the new copy before I update Lemlist."

Always review AI-generated copy that references real CVE data before it goes live — check the CVE is recent and the description is accurate.

### Re-run pipeline for fresh intel:
```bash
python pipeline.py --writeback
```

Run weekly or when new leads are added to the campaign. Updated scores overwrite the previous values in Lemlist automatically.

---

## MVP Success Criteria

Before expanding or automating:

- [ ] Connection acceptance rate ≥ 30%
- [ ] Step 3 reply rate ≥ 5%
- [ ] Pipeline returning usable findings for ≥ 60% of leads
- [ ] No LinkedIn account warnings
- [ ] ≥ 3 replies referencing the CVE or breach angle specifically

---

## What Comes After the MVP

- Shodan paid ($69/mo) — live port scanning, version-accurate CVE matching
- BuiltWith API — tech stack detection per domain for sharper CVE targeting
- Lead scoring model — weight by: CVSS score + breach recency + regulated industry
- GitHub Actions cron — weekly pipeline re-run + diff alert on new Critical/High CVEs
- MCP sequence automation — automate tag-based message selection once angles are validated
