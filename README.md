# Astarot

> Automated external recon framework for black-box web penetration testing.

Astarot automates the first reconnaissance phase of a web pentest — it takes a single root domain and attempts to map the entire wildcard scope of a company: subdomains, live hosts, open ports, WAF presence, technology stack, JS secrets, API endpoints, and known CVEs. Everything ends up in a single self-contained HTML report.

---

## Why

During a black-box web pentest the first hour is always the same: enumerate subdomains, check what's alive, fingerprint technologies, look for exposed secrets in JS bundles, map API endpoints, cross-reference findings against known CVEs. Doing this manually across dozens or hundreds of subdomains is slow and error-prone. Astarot runs all of it in parallel and hands you a report you can open in a browser and a target list you can import directly into Burp Suite.

---

## What it does

```
Domain input
    │
    ├─ Phase 0 ── Proxy validation (parallel liveness check)
    │
    ├─ Phase 1 ── Subdomain discovery (parallel)
    │               ├─ Passive OSINT  — crt.sh, HackerTarget, AlienVault OTX,
    │               │                   ThreatCrowd, urlscan.io, RapidDNS
    │               └─ Active brute   — DNS + HTTP probe against 4 989-entry
    │                                   embedded wordlist (or your own)
    │
    ├─ Phase 2 ── Deduplication + alive check
    │               └─ HTTPS → HTTP fallback, proxy-aware, status 200-399
    │
    ├─ Phase 3 ── Parallel analysis (all three run at the same time)
    │               ├─ Masscan         — fast port scan of live hosts
    │               ├─ WAF detection   — wafw00f-style fingerprinting
    │               └─ Wappalyzer      — tech stack fingerprinting
    │
    ├─ Phase 4 ── Parallel deep analysis
    │               ├─ JS Analysis
    │               │   ├─ Passive JS discovery (Wayback Machine, AlienVault)
    │               │   ├─ HTML crawl for <script src="...">
    │               │   ├─ Webpack chunk enumeration
    │               │   ├─ Framework-aware brute-force (React/Vue/Angular/Next…)
    │               │   ├─ Recursive JS scanning (depth 2)
    │               │   ├─ Secret detection — 3-tier engine:
    │               │   │     Tier 1 · 35 named rules (AWS keys, JWTs, Stripe,
    │               │   │             GitHub PATs, private keys, webhooks…)
    │               │   │     Tier 2 · 135 patterns ported from JSMiner/Nuclei
    │               │   │     Tier 3 · Shannon entropy scan (threshold 4.2 bits)
    │               │   └─ API endpoint extraction from string literals +
    │               │       fetch/axios/XHR call arguments
    │               └─ CVE Lookup
    │                   └─ NVD API 2.0 — queries every unique (technology, version)
    │                       pair detected by Wappalyzer, rate-limited to stay
    │                       within NVD free-tier (set NVD_API_KEY to go faster)
    │
    └─ Phase 5 ── HTML report generation
                    └─ report.html — fully self-contained, no server needed
```

---

## Installation

**Requirements:** Go 1.21+, Masscan (for port scanning)

```bash
go install github.com/Sneylis/Astarot/cmd/astarot@latest
```

The binary is fully self-contained — the subdomain wordlist and Wappalyzer tech database are embedded at compile time. No extra files needed.

**From source:**

```bash
git clone https://github.com/Sneylis/Astarot
cd Astarot
go build -o astarot ./cmd/astarot/
```

---

## Usage

```
astarot [flags] <domain>

Flags:
  --Wsub   <file>   Subdomain wordlist      (default: embedded 4 989-entry list)
  --Wproxy <file>   Proxy list file         (default: proxies.txt)
  -h, --help        Show help
```

**Basic scan:**

```bash
astarot example.com
```

**With a custom wordlist:**

```bash
astarot --Wsub /opt/wordlists/subdomains-top1mil.txt example.com
```

**With proxies (SOCKS5 or HTTP):**

```bash
# proxies.txt — one proxy per line
# socks5://user:pass@1.2.3.4:1080
# http://1.2.3.4:8080

astarot --Wproxy proxies.txt example.com
```

**Faster CVE scanning** — get a free API key at https://nvd.nist.gov/developers/request-an-api-key and put it in `.env`:

```bash
NVD_API_KEY=your-key-here
```

---

## Output

| File | Contents |
|---|---|
| `report.html` | Full interactive HTML report |
| `tmp/result.txt` | Live subdomains |
| `tmp/Wappalyzer.json` | Technology fingerprints per host |
| `tmp/Ports.txt` | Masscan port results |
| `tmp/js_results.json` | JS analysis per host |
| `tmp/cve_results.json` | CVE findings per host |
| `out/waf/` | WAF detection results |

### report.html

Open in any browser — no server required.

- **Stats bar** — live hosts, unique IPs, open ports, WAF count, JS files, API endpoints found, JS secrets, CVEs
- **Per-host cards** — ports, server headers, full technology table
- **JS section** (collapsible) — discovered JS files with source map detection, vendor tagging, secret count per file
- **API Endpoints** (collapsible) — color-coded by category (API, auth, admin, GraphQL)
- **Secrets** — always expanded, severity-tagged (Critical / High / Medium / Low), with surrounding context
- **CVE findings** — per host, sorted by severity then CVSS score, linked to NVD
- **Export to Burp** button — downloads a `.txt` file (one URL per line) containing all live hosts + JS URLs + full endpoint URLs, ready to load into Burp Suite Target scope

---

## Proxy support

Proxies are used for:
- Active subdomain bruteforce (all HTTP probes go through the pool)
- JS file fetching and crawling
- Alive checks

Supported formats in the proxy list:

```
socks5://1.2.3.4:1080
socks5://user:pass@1.2.3.4:1080
http://1.2.3.4:8080
```

If no working proxies are found, Astarot asks whether to continue without them.

---

## Secret detection

Three-tier engine, all patterns compiled into the binary:

| Tier | Engine | Severity |
|---|---|---|
| 1 | 35 named regex rules — AWS, GCP, GitHub, Stripe, Slack, JWT, private keys, bearer tokens, Chinese cloud providers… | Critical / High |
| 2 | 135 patterns ported from JSMiner / Nuclei template library | Medium |
| 3 | Shannon entropy (≥ 4.2 bits/char) on candidate strings | High |

Duplicates across JS files are deduplicated per host before appearing in the report.

---

## CVE lookup

Uses the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities). Queries are deduplicated — if `nginx 1.24.0` appears on 10 hosts it is queried once and the result is mapped to all hosts.

Rate limits:
- Without API key: 1 request / 7 seconds (NVD free tier)
- With `NVD_API_KEY`: 1 request / 700 ms

Results are filtered to CVEs with a CVSS score, sorted by severity, capped at 10 per technology.

---

## Notes

- Masscan requires root/administrator privileges on most systems. If it fails, port data will be absent from the report but everything else continues.
- The tool creates `tmp/` and `out/waf/` directories in the current working directory.
- All brute-force and crawl requests use a standard Chrome User-Agent to avoid trivial bot detection.
- Source maps (`.map` files) are detected and flagged — they often expose the full unminified source.
