# DNS Analyzer v2 — InboxShield Edition

A web-based DNS lookup, misconfiguration analyzer, and **email authentication security scanner**. Enter any domain — or paste a full URL like `https://example.com/page` — and get real DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) fetched concurrently, plus SPF / DMARC / DKIM analysis, an email health score, and a downloadable diagnostic report.

---

## Quick Start

### Step 1 — Install dependencies

```bash
bash setup.sh
```

This will:
- Check your Python version (3.11+ required)
- Create a `venv/` virtual environment
- Install all Python packages from `requirements.txt`

### Step 2 — Start the server

```bash
bash start.sh
```

Then open **http://127.0.0.1:8000** in your browser.

#### Custom port

```bash
bash start.sh 9000
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
| `bash setup.sh` | Creates a virtual environment and installs all dependencies |
| `bash start.sh` | Starts the web server on port 8000 (default) |
| `bash start.sh <port>` | Starts the web server on a custom port |

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

### v2 — InboxShield Email Authentication ✨ NEW
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
  - Detects: missing selectors, empty keys, testing-mode flags
- **Email Health Score**:
  - 0–100 point scoring with animated SVG ring visualization
  - Letter grades: A+ (95+), A (85+), B (70+), C (55+), D (40+), F (<40)
  - Based on combined SPF + DMARC + DKIM findings

---

## Project Structure

```
dns-analyzer/
├── app/
│   ├── main.py          # FastAPI app & routes (v2 with email auth)
│   ├── resolver.py      # Async DNS lookups (concurrent)
│   ├── analyzer.py      # 9 DNS misconfiguration checks
│   ├── spf.py           # SPF parser, lookup counter, flattener ✨
│   ├── email_auth.py    # DMARC/DKIM analysis & health scoring ✨
│   ├── models.py        # Pydantic schemas (EmailAuth, EmailScore) ✨
│   └── report.py        # Self-contained HTML report (with email auth) ✨
├── static/
│   ├── index.html       # Dashboard UI (with score ring & auth cards) ✨
│   ├── style.css        # Design system (Geist fonts, dark theme)
│   └── app.js           # Frontend rendering (email auth visualizations) ✨
├── setup.sh             # Install dependencies
├── start.sh             # Start the web server
├── Dockerfile           # Container image build
├── .dockerignore        # Exclude local files from image builds
├── requirements.txt     # Python dependencies
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
