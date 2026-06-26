#!/usr/bin/env python3
"""
Cyberdebunk Security Intelligence Pipeline

Fetches leads from a Lemlist campaign, enriches each company with
CVE and breach data, and optionally writes results back as Lemlist
custom variables.

Usage:
    python pipeline.py                      # dry run, generates report
    python pipeline.py --writeback          # push variables to Lemlist
    python pipeline.py --limit 5            # test with first 5 leads
    python pipeline.py --campaign <id>      # override campaign ID
"""

import os
import re
import sys
import time
import json
import argparse
import subprocess
import requests
from datetime import datetime, timedelta
from pathlib import Path
from base64 import b64encode


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CAMPAIGN_ID = os.getenv("LEMLIST_CAMPAIGN_ID", "cam_D4cKonCgWRYoNiEDR")

NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HIBP_BASE    = "https://haveibeenpwned.com/api/v3"
CENSYS_BASE  = "https://search.censys.io/api/v2"
LEMLIST_BASE = "https://api.lemlist.com/api"

TECH_STACK_DEFAULTS = [
    "Apache HTTP Server", "nginx", "Microsoft IIS",
    "OpenSSL", "WordPress", "Apache Tomcat",
]

VT_BASE       = "https://www.virustotal.com/api/v3"
SSL_LABS_BASE = "https://api.ssllabs.com/api/v3"

_WHOIS_DATE_PATS = [
    re.compile(r"creation date:\s*(\S+)", re.I),
    re.compile(r"created:\s*(\S+)", re.I),
    re.compile(r"registered:\s*(\S+)", re.I),
]
_WHOIS_DATE_FMTS = [
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d", "%d-%b-%Y", "%d/%m/%Y",
]

# Domains that belong to individuals, not the company
PERSONAL_EMAIL_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com"}


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _lemlist_auth() -> dict:
    key = os.getenv("LEMLIST_API_KEY", "")
    if not key:
        raise EnvironmentError("LEMLIST_API_KEY not set")
    token = b64encode(f":{key}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


def _censys_auth():
    uid    = os.getenv("CENSYS_API_ID", "")
    secret = os.getenv("CENSYS_API_SECRET", "")
    return (uid, secret) if uid and secret else None


def _nvd_sleep() -> float:
    return 0.7 if os.getenv("NVD_API_KEY") else 6.5


def _nvd_headers() -> dict:
    h = {"User-Agent": "CyberdebunkIntel/1.0"}
    key = os.getenv("NVD_API_KEY", "")
    if key:
        h["apiKey"] = key
    return h


# ---------------------------------------------------------------------------
# Lead parsing
# ---------------------------------------------------------------------------

def extract_company(tagline: str, domain: str) -> str:
    """
    Pull company name from a LinkedIn tagline like 'CTO at MindDoc'
    or 'CISO @ Mediaire'. Falls back to title-casing the domain root.
    """
    if tagline:
        # "Title at/@ Company [| extra]"
        m = re.search(r'(?:^|\s)(?:at|@)\s+(.+?)(?:\s*[|·•–].*)?$', tagline, re.IGNORECASE)
        if m:
            name = m.group(1).strip()
            # Drop anything after secondary delimiter
            name = re.split(r'\s*[|·•–]\s*', name)[0].strip()
            if len(name) > 2:
                return name
    # Fall back: title-case the domain root (e.g. minddoc.de → Minddoc)
    root = domain.split(".")[0] if domain else "Unknown"
    return root.replace("-", " ").title()


def email_domain(email: str) -> str | None:
    """Extract company domain from work email. Returns None for personal domains."""
    if "@" not in email:
        return None
    dom = email.split("@")[1].lower()
    return None if dom in PERSONAL_EMAIL_DOMAINS else dom


# ---------------------------------------------------------------------------
# Lemlist API
# ---------------------------------------------------------------------------

def fetch_leads(campaign_id: str) -> list[dict]:
    """
    Returns fully enriched leads by joining the campaign leads list
    with each contact record. Each item has:
      email, domain, company, full_name, tagline, linkedin_url,
      contact_id, lead_id
    """
    headers = _lemlist_auth()

    # Step 1: get lead stubs (id + contactId only)
    resp = requests.get(
        f"{LEMLIST_BASE}/campaigns/{campaign_id}/leads",
        headers=headers, timeout=30,
    )
    resp.raise_for_status()
    stubs = resp.json()
    if not isinstance(stubs, list):
        stubs = stubs.get("leads", stubs.get("data", []))

    # Step 2: fetch full contact for each stub
    leads = []
    for stub in stubs:
        contact_id = stub.get("contactId")
        if not contact_id:
            continue
        cr = requests.get(
            f"{LEMLIST_BASE}/contacts/{contact_id}",
            headers=headers, timeout=15,
        )
        if cr.status_code != 200:
            continue
        c = cr.json()
        fields  = c.get("fields", {})
        email   = c.get("email", "")
        dom     = email_domain(email)
        tagline = fields.get("tagline", "")
        company = extract_company(tagline, dom or "")
        leads.append({
            "lead_id":     stub.get("_id", ""),
            "contact_id":  contact_id,
            "email":       email,
            "domain":      dom,
            "company":     company,
            "full_name":   c.get("fullName", ""),
            "tagline":     tagline,
            "linkedin_url": c.get("linkedinUrl", ""),
            "location":    fields.get("location", ""),
            "job_title":   fields.get("jobTitle", ""),
        })

    return leads


def writeback_lead(campaign_id: str, email: str, variables: dict) -> bool:
    """Push custom variables to a Lemlist lead (by email address)."""
    resp = requests.patch(
        f"{LEMLIST_BASE}/campaigns/{campaign_id}/leads/{email}",
        headers=_lemlist_auth(),
        json=variables,
        timeout=30,
    )
    return resp.status_code in (200, 201, 204)


# ---------------------------------------------------------------------------
# VirusTotal — passive tech stack hints (free, 500 req/day)
# ---------------------------------------------------------------------------

def query_virustotal(domain: str) -> list[str]:
    """Return tech stack clues from VT passive DNS / HTTP response headers."""
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        return []
    try:
        resp = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers={"x-apikey": key},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        data  = resp.json().get("data", {}).get("attributes", {})
        # Last HTTP response headers often contain Server / X-Powered-By
        headers = data.get("last_http_response_headers", {})
        server  = headers.get("server", "") + " " + headers.get("x-powered-by", "")
        cats    = " ".join(data.get("categories", {}).values())
        combined = (server + " " + cats).lower()
        signals = {
            "Apache HTTP Server": ["apache"],
            "nginx":              ["nginx"],
            "Microsoft IIS":      ["iis", "microsoft-iis"],
            "ASP.NET":            ["asp.net"],
            "WordPress":          ["wordpress"],
            "Drupal":             ["drupal"],
            "OpenSSL":            ["openssl"],
            "PHP":                ["php"],
            "Node.js / Express":  ["node.js", "express"],
            "Cloudflare":         ["cloudflare"],
        }
        return [t for t, terms in signals.items() if any(s in combined for s in terms)]
    except Exception as e:
        print(f"    [VT] error for {domain}: {e}")
        return []


# ---------------------------------------------------------------------------
# SSL Labs — SSL grade from cached scan (free, no key, no new scan triggered)
# ---------------------------------------------------------------------------

def query_ssl_labs(domain: str) -> dict:
    """Return SSL grade and cert expiry from SSL Labs cache. Empty dict on cache miss."""
    try:
        resp = requests.get(
            f"{SSL_LABS_BASE}/analyze",
            params={"host": domain, "fromCache": "on", "maxAge": "48"},
            headers={"User-Agent": "CyberdebunkIntel/1.0"},
            timeout=20,
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        if data.get("status") != "READY":
            return {}
        endpoints = data.get("endpoints", [])
        grade = endpoints[0].get("grade", "") if endpoints else ""
        certs = data.get("certs", [])
        expiry = ""
        if certs:
            ts = certs[0].get("notAfter", 0)
            if ts:
                expiry = datetime.utcfromtimestamp(ts / 1000).strftime("%Y-%m-%d")
        return {"grade": grade, "cert_expiry": expiry}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Whois — domain age and registrar via CLI
# ---------------------------------------------------------------------------

def query_whois(domain: str) -> dict:
    """Return domain age in days and registrar from whois CLI."""
    try:
        out = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        ).stdout
        age_days, registrar = None, ""
        for line in out.splitlines():
            if not age_days:
                for pat in _WHOIS_DATE_PATS:
                    m = pat.search(line)
                    if m:
                        ds = m.group(1)[:19]
                        for fmt in _WHOIS_DATE_FMTS:
                            try:
                                age_days = (datetime.now() - datetime.strptime(ds, fmt)).days
                                break
                            except ValueError:
                                pass
                        if age_days:
                            break
            if not registrar and re.match(r"registrar:", line, re.I):
                registrar = line.split(":", 1)[1].strip()[:60]
        return {"age_days": age_days, "registrar": registrar}
    except Exception:
        return {"age_days": None, "registrar": ""}


# ---------------------------------------------------------------------------
# Censys scanning (free programmatic access removed June 2026 — inferred only)
# ---------------------------------------------------------------------------

def scan_censys(domain: str) -> dict:
    auth = _censys_auth()
    if not auth:
        return _no_scan()
    try:
        resp = requests.get(
            f"{CENSYS_BASE}/hosts/search",
            auth=auth,
            params={"q": domain, "per_page": 1},
            timeout=20,
        )
        if resp.status_code == 429:
            print(f"    [Censys] rate-limited on {domain}")
            return _no_scan()
        if resp.status_code != 200:
            return _no_scan()
        hits = resp.json().get("result", {}).get("hits", [])
        if not hits:
            return _no_scan()
        services = hits[0].get("services", [])
        ports    = [s.get("port") for s in services if s.get("port")]
        names    = list({s.get("service_name", "") for s in services if s.get("service_name")})
        banners  = {s["port"]: s["banner"] for s in services if s.get("banner")}
        return {"ports": ports, "services": names, "banners": banners, "data_source": "live_scan"}
    except Exception as e:
        print(f"    [Censys] error: {e}")
        return _no_scan()


def _no_scan() -> dict:
    return {"ports": [], "services": [], "banners": {}, "data_source": "inferred"}


# ---------------------------------------------------------------------------
# NVD CVE lookup
# ---------------------------------------------------------------------------

def query_nvd(keyword: str, max_results: int = 50) -> list[dict]:
    time.sleep(_nvd_sleep())
    # pubStartDate causes 503/404 under rate-limiting without an API key.
    # With a key the endpoint is stable — enable date filtering to get recent CVEs.
    cutoff = datetime.now() - timedelta(days=3 * 365)
    key = os.getenv("NVD_API_KEY", "")
    params = {
        "keywordSearch":  keyword,
        "resultsPerPage": max_results,
    }
    if key:
        params["apiKey"]       = key
        params["pubStartDate"] = cutoff.strftime("%Y-%m-%dT00:00:00.000")
        params["sortBy"]       = "published"
        params["sortOrder"]    = "dsc"
    try:
        for attempt in range(3):
            try:
                resp = requests.get(NVD_BASE, params=params, headers=_nvd_headers(), timeout=30)
            except requests.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(10 * (attempt + 1))
                    continue
                return []
            if resp.status_code == 403:
                print(f"    [NVD] rate-limited on '{keyword}' — sleeping 35s")
                time.sleep(35)
                continue
            if resp.status_code in (503, 502, 500):
                wait = 15 * (attempt + 1)
                print(f"    [NVD] {resp.status_code} on '{keyword}' — retry in {wait}s")
                time.sleep(wait)
                continue
            break
        resp.raise_for_status()
        results = []
        for v in resp.json().get("vulnerabilities", []):
            cve   = v.get("cve", {})
            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            score, severity = _extract_cvss(cve.get("metrics", {}))
            # Keep HIGH (>=7.0) and CRITICAL (>=9.0) only
            if score is not None and score < 7.0:
                continue
            # Client-side date filter — only when key is present (server already filtered);
            # without key, pubStartDate and sortOrder are unsupported (NVD 404s).
            if key:
                pub = cve.get("published", "")
                if pub and pub < cutoff.strftime("%Y-%m-%d"):
                    continue
            results.append({
                "id":          cve.get("id", ""),
                "description": desc[:300],
                "cvss_score":  score,
                "severity":    severity,
                "keyword":     keyword,
            })
        return results
    except Exception as e:
        print(f"    [NVD] error for '{keyword}': {e}")
        return []


def _extract_cvss(metrics: dict) -> tuple:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            d = entries[0].get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity", "")
    return None, ""


def get_top_cve(cves: list[dict]) -> dict | None:
    scored = [c for c in cves if c.get("cvss_score") is not None]
    return max(scored, key=lambda c: c["cvss_score"]) if scored else (cves[0] if cves else None)


# ---------------------------------------------------------------------------
# HIBP breach lookup
# ---------------------------------------------------------------------------

def query_hibp(domain: str, hibp_key: str = "", months: int = 24) -> list[dict]:
    if not hibp_key:
        return []
    try:
        resp = requests.get(
            f"{HIBP_BASE}/breaches",
            params={"domain": domain},
            headers={"hibp-api-key": hibp_key, "User-Agent": "CyberdebunkIntel/1.0"},
            timeout=20,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        cutoff  = datetime.now() - timedelta(days=months * 30)
        recent  = []
        for b in resp.json():
            try:
                if datetime.strptime(b.get("BreachDate", ""), "%Y-%m-%d") >= cutoff:
                    recent.append({
                        "name":      b.get("Name", ""),
                        "date":      b.get("BreachDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                    })
            except ValueError:
                pass
        return recent
    except Exception as e:
        print(f"    [HIBP] error for {domain}: {e}")
        return []


# ---------------------------------------------------------------------------
# Tech stack detection
# ---------------------------------------------------------------------------

def detect_tech(censys: dict) -> list[str]:
    combined = (
        " ".join(s.lower() for s in censys.get("services", []))
        + " "
        + " ".join(str(v).lower() for v in censys.get("banners", {}).values())
    )
    signals = {
        "Apache HTTP Server": ["apache", "httpd"],
        "nginx":              ["nginx"],
        "Microsoft IIS":      ["iis", "microsoft-iis"],
        "ASP.NET":            ["asp.net"],
        "WordPress":          ["wordpress", "wp-content"],
        "Drupal":             ["drupal"],
        "Apache Tomcat":      ["tomcat", "catalina"],
        "OpenSSL":            ["openssl"],
        "PHP":                ["php"],
        "Node.js / Express":  ["node.js", "express"],
    }
    found = [tech for tech, terms in signals.items() if any(t in combined for t in terms)]
    return found or TECH_STACK_DEFAULTS[:3]


# ---------------------------------------------------------------------------
# Lead enrichment
# ---------------------------------------------------------------------------

def analyze_lead(lead: dict, hibp_key: str = "", verbose: bool = False) -> dict:
    company = lead["company"]
    domain  = lead.get("domain") or ""

    print(f"\n  [{company}]  {domain}")

    if not domain:
        print(f"    no domain — skipping scan")
        tag       = "no_findings"
        variables = _empty_variables(tag)
        return {**lead, "tech_stack": [], "top_cve": None, "cve_count": 0,
                "breaches": [], "tag": tag, "data_source": "inferred", "variables": variables}

    # Censys (inferred only — free API removed June 2026)
    censys = scan_censys(domain)
    print(f"    censys: {censys['data_source']}", end="")
    if censys["data_source"] == "live_scan":
        print(f" — ports {censys['ports'][:5]}, services {censys['services'][:4]}")
    else:
        print()

    # VirusTotal — supplements tech stack when no live scan
    vt_tech = query_virustotal(domain) if censys["data_source"] == "inferred" else []
    if vt_tech and verbose:
        print(f"    vt tech: {vt_tech}")

    # SSL Labs — cached grade, no new scan triggered
    ssl = query_ssl_labs(domain)
    if ssl.get("grade") and verbose:
        print(f"    ssl grade: {ssl['grade']}  (cert expires {ssl.get('cert_expiry', '?')})")

    # Whois — domain age and registrar
    whois = query_whois(domain)
    if whois.get("age_days") and verbose:
        print(f"    domain age: {whois['age_days'] // 365}y  ({whois.get('registrar', '')})")

    # Tech + CVEs
    tech     = detect_tech(censys) if censys["data_source"] == "live_scan" else (vt_tech or TECH_STACK_DEFAULTS[:3])
    all_cves = []
    for t in tech[:6]:
        cves = query_nvd(t)
        all_cves.extend(cves)
        if verbose and cves:
            print(f"    nvd '{t}': {len(cves)} CVEs")
    top_cve = get_top_cve(all_cves)

    # HIBP
    breaches = query_hibp(domain, hibp_key)
    breach   = breaches[0] if breaches else None

    # Tag
    if top_cve:
        tag = "has_cve"
    elif breach:
        tag = "has_breach"
    else:
        tag = "no_findings"

    ports_str   = ",".join(str(p) for p in censys["ports"][:5]) or "unknown"
    service_str = (censys["services"] or tech or ["unknown"])[0]

    variables = {
        "cvss_score":      str(top_cve["cvss_score"]) if top_cve and top_cve.get("cvss_score") else "",
        "key_risk":        top_cve["severity"]        if top_cve and top_cve.get("severity")   else "",
        "exposed_ports":   ports_str,
        "top_cve":         top_cve["id"]              if top_cve else "",
        "key_cve":         top_cve["id"]              if top_cve else "",
        "exposed_service": service_str,
        "breach_date":     breach["date"]             if breach  else "",
        "compliance_flag": "GDPR breach flagged"      if breach  else "",
        "ssl_grade":       ssl.get("grade", ""),
        "domain_age":      f"{whois['age_days'] // 365}y" if whois.get("age_days") else "",
        "lemlistTag":      tag,
    }

    print(f"    tag: {tag}", end="")
    if top_cve and top_cve.get("cvss_score"):
        print(f"  |  {top_cve['id']} CVSS {top_cve['cvss_score']}", end="")
    if breach:
        print(f"  |  breach {breach['date']}", end="")
    print()

    return {
        **lead,
        "tech_stack":  tech,
        "top_cve":     top_cve,
        "cve_count":   len(all_cves),
        "breaches":    breaches,
        "tag":         tag,
        "data_source": censys["data_source"],
        "ssl_grade":   ssl.get("grade", ""),
        "cert_expiry": ssl.get("cert_expiry", ""),
        "domain_age":  whois.get("age_days"),
        "registrar":   whois.get("registrar", ""),
        "variables":   variables,
    }


def _empty_variables(tag: str) -> dict:
    return {
        "cvss_score": "", "key_risk": "", "exposed_ports": "unknown",
        "top_cve": "", "key_cve": "", "exposed_service": "unknown",
        "breach_date": "", "compliance_flag": "",
        "ssl_grade": "", "domain_age": "", "lemlistTag": tag,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def generate_report(results: list[dict], writeback: bool = False) -> str:
    now      = datetime.now().strftime("%Y-%m-%d %H:%M")
    total    = len(results)
    n_cve    = sum(1 for r in results if r["tag"] == "has_cve")
    n_breach = sum(1 for r in results if r["tag"] == "has_breach")
    n_none   = sum(1 for r in results if r["tag"] == "no_findings")
    usable   = n_cve + n_breach
    rate     = usable / total if total else 0
    live     = sum(1 for r in results if r.get("data_source") == "live_scan")
    mark     = "✓ above" if rate >= 0.60 else "✗ below"

    lines = [
        "# Security Intelligence Report",
        f"Generated: {now}",
        "",
        "## Run Summary",
        "| Metric | Value |",
        "|---|---|",
        f"| Total leads | {total} |",
        f"| `has_cve` | {n_cve} |",
        f"| `has_breach` | {n_breach} |",
        f"| `no_findings` | {n_none} |",
        f"| Usable intel rate | {rate:.0%} — {mark} MVP threshold (60%) |",
        f"| Live Censys scans | {live}/{total} |",
        f"| Writeback | {'yes' if writeback else 'dry run'} |",
        "",
        "## Lead Table",
        "| Company | Domain | Tag | CVE | CVSS | SSL | Domain Age | Breach |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        cve_id     = r["top_cve"]["id"]              if r.get("top_cve") else "—"
        cvss       = str(r["top_cve"]["cvss_score"]) if r.get("top_cve") and r["top_cve"].get("cvss_score") else "—"
        ssl_grade  = r.get("ssl_grade") or "—"
        age        = f"{r['domain_age'] // 365}y" if r.get("domain_age") else "—"
        breach     = r["variables"].get("breach_date") or "—"
        lines.append(
            f"| {r['company']} | {r.get('domain','—')} | `{r['tag']}` | {cve_id} | {cvss} | {ssl_grade} | {age} | {breach} |"
        )

    lines += ["", "---", "", "## Lead Details"]
    for r in results:
        v = r["variables"]
        lines += [
            f"### {r['company']}  ({r.get('full_name', '')})",
            f"**Domain:** `{r.get('domain', 'unknown')}` | "
            f"**Data source:** `{r.get('data_source', 'inferred')}`",
            f"**Role:** {r.get('job_title', '')} — {r.get('tagline', '')[:80]}",
            f"**Tag:** `{r['tag']}`",
        ]
        tech = r.get("tech_stack", [])
        if tech:
            lines.append(f"**Tech stack:** {', '.join(tech[:6])}")
        meta_parts = []
        if r.get("ssl_grade"):
            expiry = f" (expires {r['cert_expiry']})" if r.get("cert_expiry") else ""
            meta_parts.append(f"SSL grade **{r['ssl_grade']}**{expiry}")
        if r.get("domain_age"):
            reg = f" via {r['registrar']}" if r.get("registrar") else ""
            meta_parts.append(f"domain age **{r['domain_age'] // 365}y**{reg}")
        if meta_parts:
            lines.append("**Recon:** " + "  |  ".join(meta_parts))
        if r.get("top_cve"):
            c = r["top_cve"]
            lines += [
                f"**CVE:** [{c['id']}](https://nvd.nist.gov/vuln/detail/{c['id']}) "
                f"— CVSS **{c.get('cvss_score', '?')}** ({c.get('severity', '?')})",
                f"> {c.get('description', '')[:250]}",
            ]
        if v.get("breach_date"):
            lines.append(f"**Breach:** {v['breach_date']} — {v.get('compliance_flag', '')}")
        lines += [
            "",
            "**Lemlist variables:**",
            f"  `{{{{cvss_score}}}}` = {v['cvss_score'] or '(empty)'}",
            f"  `{{{{key_cve}}}}` = {v['key_cve'] or '(empty)'}",
            f"  `{{{{exposed_service}}}}` = {v['exposed_service']}",
            f"  `{{{{exposed_ports}}}}` = {v['exposed_ports']}",
            f"  `{{{{ssl_grade}}}}` = {v['ssl_grade'] or '(empty)'}",
            f"  `{{{{domain_age}}}}` = {v['domain_age'] or '(empty)'}",
            f"  `{{{{breach_date}}}}` = {v['breach_date'] or '(empty)'}",
            f"  `{{{{compliance_flag}}}}` = {v['compliance_flag'] or '(empty)'}",
            "",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Cyberdebunk Security Intel Pipeline")
    parser.add_argument("--campaign",  default=CAMPAIGN_ID)
    parser.add_argument("--writeback", action="store_true", help="Push variables to Lemlist")
    parser.add_argument("--hibp-key",  default=os.getenv("HIBP_API_KEY", ""))
    parser.add_argument("--output",    default="intel_report.md")
    parser.add_argument("--limit",     type=int, default=0, help="Max leads (0 = all)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not os.getenv("LEMLIST_API_KEY"):
        print("Error: LEMLIST_API_KEY is not set. Copy .env.example → .env")
        sys.exit(1)

    if not os.getenv("NVD_API_KEY"):
        print("Note: NVD_API_KEY not set — slow mode (~7min). Free key: nvd.nist.gov\n")
    if not _censys_auth():
        print("Note: Censys keys not set — live scanning disabled. Free: censys.io/account/api\n")

    print(f"Fetching leads from campaign {args.campaign}...")
    leads = fetch_leads(args.campaign)
    if args.limit:
        leads = leads[:args.limit]
    print(f"{len(leads)} leads loaded\n")

    print("Running enrichment...")
    results = [
        analyze_lead(lead, hibp_key=args.hibp_key, verbose=args.verbose)
        for lead in leads
    ]

    if args.writeback:
        print("\nWriting back to Lemlist...")
        ok = 0
        for r in results:
            if r["email"]:
                if writeback_lead(args.campaign, r["email"], r["variables"]):
                    ok += 1
                    if args.verbose:
                        print(f"  ✓ {r['company']}")
                else:
                    print(f"  ✗ {r['company']} ({r['email']})")
        print(f"Writeback: {ok}/{len(results)} updated")

    report = generate_report(results, writeback=args.writeback)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"\nReport → {args.output}")

    n_cve    = sum(1 for r in results if r["tag"] == "has_cve")
    n_breach = sum(1 for r in results if r["tag"] == "has_breach")
    n_none   = sum(1 for r in results if r["tag"] == "no_findings")
    print(f"Summary: {n_cve} CVE  |  {n_breach} breach  |  {n_none} no findings")


if __name__ == "__main__":
    main()
