# DNS Analyzer v2 — InboxShield Edition

A web-based DNS lookup, misconfiguration analyzer, and **email authentication security scanner**. Enter any domain — or paste a full URL like `https://example.com/page` — and get real DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) fetched concurrently, plus SPF / DMARC / DKIM analysis, an email health score, and a downloadable diagnostic report.

---

## Quick Start

### One-Command Setup & Launch (Recommended)

```bash
bash run.sh
```

This all-in-one script will:
- Check your Python version (3.11+ required)
- Automatically verify or create the `venv/` virtual environment
- Install any missing dependencies from `requirements.txt`
- Start the server on **http://127.0.0.1:8000**

#### Custom port

```bash
bash run.sh 9000
```

#### Setup only (without launching server)

```bash
bash run.sh --setup-only
```

### Run with Docker

Build the image from the project directory:

```bash
docker build -t dns-analyzer .
```

Run it and open **http://127.0.0.1:8000**:

```bash
docker run --rm -p 8000:8000 dns-analyzer
```

To use another host port, map it to container port 8000, for example:

```bash
docker run --rm -p 9000:8000 dns-analyzer
```

---

## Scripts

| Script | What it does |
|--------|-------------|
| `bash run.sh` | **Unified runner:** verifies environment, auto-installs dependencies, and launches server |
| `bash run.sh <port>` | Starts the server on a custom port (e.g. `9000`) |
| `bash run.sh --setup-only` | Installs dependencies and prepares `venv` without launching the server |

---

## Usage

1. Paste any **domain** or **full URL** into the input box and press **Analyze**
2. Examples of accepted input:
   - `example.com`
   - `www.boot.dev`
   - `https://www.boot.dev/dashboard`
   - `https://github.com/user/repo?tab=stars`
3. The hostname is automatically extracted from URLs — no need to clean it up manually
4. View the **Email Health Score** (A+ to F) and **SPF / DMARC / DKIM** authentication cards
5. Click **Download Report** to save a standalone HTML report of the results

---

## Features

### v1 — DNS Infrastructure Analysis
- Concurrent DNS resolution via `asyncio.gather` — all record types in one round trip
- Accepts full URLs — automatically extracts the hostname
- Rule-based analyzer with 9 check categories:
  - Domain IP resolution
  - NS record existence & redundancy
  - NS host reachability
  - MX record existence & host reachability
  - CNAME conflict detection (RFC 1034)
  - SOA sanity (refresh/retry/expire values)
  - TTL sanity (zero TTL, extremely high TTL)
- Color-coded findings dashboard (error / warning / info)
- Summary badges (errors / warnings / info counts)
- Downloadable self-contained HTML report (works offline)
- Clean 400 errors for invalid input — no silent failures
- Accessible UI: skip link, `aria-live`, `:focus-visible` rings, reduced-motion support

### v2 — InboxShield Email & Enterprise Security Suite ✨
- **SPF Analysis** (RFC 7208):
  - Parse SPF TXT records into structured data
  - Recursive DNS lookup counting against the 10-lookup limit
  - SPF record flattening — auto-generates an optimized `ip4`/`ip6`-only record
  - Detects: missing SPF, multiple SPF records, `+all`, `?all`, deprecated `ptr` mechanism, oversized records
- **DMARC Analysis** (RFC 7489):
  - Fetch and parse `_dmarc.{domain}` TXT records
  - Policy strength grading: `none` → `quarantine` → `reject`
  - Detects: missing DMARC, weak policies, no aggregate reporting, partial enforcement (`pct < 100`)
- **DKIM Analysis** (RFC 6376):
  - Concurrent scan of 15 common selectors (`google`, `default`, `selector1`, `selector2`, `s1`, `s2`, `dkim`, `mail`, `k1`, `mandrill`, `zendesk`, `amazonses`, etc.)
  - Public key extraction and validation
- **Subdomain Takeover Defense Scanner** (CVE Threat Hunting):
  - Analyzes CNAME pointers against known cloud provider fingerprints (AWS S3, GitHub Pages, Heroku, Shopify, Zendesk, Surge, Ghost, Azure, Vercel)
  - Detects dangling CNAMEs pointing to unresolvable/decommissioned endpoints before attackers hijack them
- **DNSSEC Cryptographic Chain-of-Trust** (RFC 4033, 4034, 4035):
  - Audits Key Signing Keys (KSK), Zone Signing Keys (ZSK), algorithms (ECDSA, Ed25519, RSA), and parent DS delegation records
  - Verifies immunity against DNS cache poisoning (Kaminsky attacks)
- **BIMI Brand Certification** (RFC 8617):
  - Audits `default._bimi.{domain}` for verified company logo display in Gmail, Apple Mail, and Yahoo Mail
- **1-Click Remediation & BIND Zone File Generator**:
  - Automatically generates tailored copy-paste DNS records for Cloudflare, AWS Route 53, and GoDaddy
  - Exportable RFC-standard BIND zone file (`.zone`) with one click
- **Design Engineering & UI/UX Craft** (Inspired by Linear, Vercel, Stripe, Raycast & Apple):
  - **Keyboard-First Ergonomics**: Instant navigation with `/` to search, `?` for shortcuts modal, `1`–`4` for sample chips, `f` for severity filter cycling, `d` for offline reports, and `z` for BIND zone export
  - **Executive Posture Matrix**: 4-quadrant high-level health overview (Routing, Redundancy, Email Defense, DNSSEC)
  - **Smart Provider Intelligence**: Auto-detects MX & NS providers (Google Workspace, Microsoft 365, Cloudflare, Route 53) and categorizes cryptic TXT verification records (SPF, Google, Apple, Stripe, GitHub)
  - **Actionable 1-Click Resolution**: Copyable DNS records with checkmark affirmations and humanized time intervals (`7200s (2 hrs)`)
  - **Sticky Jump Navigation & Frosted Glass Toast**: Blur backdrops (`backdrop-filter`), active scroll tracking, and 350ms staggered card reveals

---

## Project Structure

```
dns-analyzer/
├── app/
│   ├── main.py          # FastAPI app & routes (high-concurrency gateway)
│   ├── resolver.py      # Async DNS lookups (concurrent)
│   ├── analyzer.py      # 9 DNS infrastructure checks
│   ├── spf.py           # SPF parser, lookup counter, flattener
│   ├── email_auth.py    # DMARC/DKIM analysis & health scoring
│   ├── dnssec.py        # DNSSEC cryptographic chain-of-trust audit ✨
│   ├── takeover.py      # Subdomain takeover & dangling CNAME detector ✨
│   ├── bimi.py          # BIMI brand logo email inbox validator ✨
│   ├── remediation.py   # 1-Click DNS fix & BIND zone file generator ✨
│   ├── models.py        # Pydantic request/response schemas
│   └── report.py        # Standalone offline HTML diagnostic reports
├── static/
│   ├── index.html       # Dashboard UI with Quick Chips & Remediation Wizard
│   ├── style.css        # Geist design system (dark theme)
│   └── app.js           # Frontend logic, filter tabs, copy triggers, SVG ring
├── run.sh               # Single all-in-one script (auto-setup & launch)
├── Dockerfile           # Container image build
├── .dockerignore        # Exclude local files from image builds
├── requirements.txt     # Python dependencies
├── PRESENTATION.md      # Master demo script, architecture & viva Q&A
├── .gitignore
└── README.md
```

---

## Tech Stack

| Layer     | Technology                              |
|-----------|-----------------------------------------|
| Backend   | Python 3.11+, FastAPI, dnspython        |
| Server    | uvicorn (ASGI)                          |
| Frontend  | Plain HTML + CSS + Vanilla JS (no framework) |
| Templates | Jinja2 (report generation)              |
| DNS       | dnspython async resolver                |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Serves the dashboard |
| `POST` | `/api/analyze` | Runs a full DNS + email auth analysis. Body: `{ "domain": "example.com" }` |
| `GET`  | `/api/report/{domain}` | Downloads a standalone HTML report with email auth data |

### API Response (v2)

The `/api/analyze` response now includes an `email_auth` object:

```json
{
  "domain": "example.com",
  "scan_timestamp": "2024-01-01 12:00:00 UTC",
  "records": { ... },
  "findings": [ ... ],
  "summary": { "errors": 0, "warnings": 1, "info": 5 },
  "email_auth": {
    "spf": { "raw": "v=spf1 ...", "all_mechanism": "-all", ... },
    "spf_lookups": { "total_lookups": 7, "limit": 10, "over_limit": false },
    "spf_flattened": { "flattened_record": "v=spf1 ip4:... -all" },
    "dmarc": { "raw": "v=DMARC1; p=reject; ...", "policy": "reject", "pct": 100 },
    "dkim": { "has_dkim": true, "selectors_found": [ ... ] },
    "score": { "score": 92, "grade": "A", "label": "Good" }
  }
}
```

---

## RFC Standards Referenced

| RFC | Standard | What We Check |
|-----|----------|---------------|
| RFC 1034 / 1035 | DNS Specification | CNAME conflicts, NS requirements |
| RFC 1912 / 2182 | DNS Operations | SOA refresh/retry/expire sanity |
| RFC 5321 | SMTP | MX record existence & reachability |
| RFC 7208 | SPF | Record parsing, 10-lookup limit, policy analysis |
| RFC 7489 | DMARC | Policy parsing, enforcement, reporting |
| RFC 6376 | DKIM | Selector discovery, key validation |

---

## Future Scope (v3 ideas)

- DNSSEC chain-of-trust verification
- Subdomain takeover detection
- Wildcard DNS detection
- Scan history / database (PostgreSQL)
- Bulk domain scanning
- Webhook alerts (Slack/Discord)
- PDF export
- User accounts / auth
