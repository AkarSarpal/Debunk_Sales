# Debunk Sales — Security Intelligence Pipeline

Enriches Lemlist leads with real security data (CVEs, SSL grades, domain age, breach history) and pushes it back as custom variables for personalised cold outreach.

---

## How it works

1. Reads all leads from a Lemlist campaign via API
2. Resolves company domain from each lead's work email
3. Pulls security intel per domain:
   - **NVD** — HIGH/CRITICAL CVEs from the last 3 years
   - **VirusTotal** — passive tech stack hints from cached HTTP headers
   - **SSL Labs** — SSL grade from cached scan (no new scan triggered)
   - **Whois** — domain age and registrar
   - **HIBP** — breach date and GDPR flag (requires paid key)
4. Tags each lead: `has_cve`, `has_breach`, or `no_findings`
5. Optionally writes 10 variables back to Lemlist with `--writeback`

## Lemlist variables injected

`{{cvss_score}}` `{{key_cve}}` `{{exposed_service}}` `{{exposed_ports}}` `{{ssl_grade}}` `{{domain_age}}` `{{breach_date}}` `{{compliance_flag}}` `{{key_risk}}` `{{lemlistTag}}`

## Setup

```bash
cp .env.example .env
# fill in at minimum: LEMLIST_API_KEY
pip install requests
```

## Usage

```bash
# dry run — generates intel_report.md, no changes to Lemlist
python pipeline.py

# test on first 3 leads
python pipeline.py --limit 3 -v

# push all variables to Lemlist (activate campaign in UI first)
python pipeline.py --writeback
```

## API keys

| Key | Required | Where to get |
|---|---|---|
| `LEMLIST_API_KEY` | Yes | Lemlist → Settings → Integrations |
| `NVD_API_KEY` | No (recommended) | nvd.nist.gov → Request API Key — cuts runtime 7min → 40sec |
| `VIRUSTOTAL_API_KEY` | No | virustotal.com/gui/join-us — free, 500 req/day |
| `HIBP_API_KEY` | No | haveibeenpwned.com/API/Key — ~$4/mo, enables breach angle |

Without an NVD key, the pipeline runs in slow mode (~7 min for 23 leads). Without a VirusTotal key, tech stack defaults to Apache/nginx/IIS generics.

## Intel quality

Every result carries `data_source: inferred` or `live_scan`. Currently all results are `inferred` — CVEs are real but matched to detected or default tech stack, not a verified running service. Treat findings as conversation starters, not audit-grade claims.

Live scanning (port fingerprinting + version-accurate CVEs) requires Shodan paid ($69/mo).

## Output

`intel_report.md` is generated per run with a lead table and per-lead variable preview. It is gitignored and never committed.
