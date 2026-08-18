# DNS Analyzer

A web-based DNS lookup and misconfiguration analyzer. Enter any domain — or paste a full URL like `https://example.com/page` — and get real DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) fetched concurrently, plus a rule-based findings report.

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
4. Click **Download Report** to save a standalone HTML report of the results

---

## Features (v1)

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

---

## Project Structure

```
dns-analyzer/
├── app/
│   ├── main.py        # FastAPI app & routes
│   ├── resolver.py    # Async DNS lookups (concurrent)
│   ├── analyzer.py    # Misconfiguration checks
│   ├── models.py      # Pydantic request/response schemas
│   └── report.py      # Self-contained HTML report generator
├── static/
│   ├── index.html     # Dashboard UI
│   ├── style.css      # Design system (Geist fonts, dark theme)
│   └── app.js         # Fetch, DOM rendering, URL parsing
├── setup.sh           # Install dependencies
├── start.sh           # Start the web server
├── requirements.txt   # Python dependencies
├── .gitignore
└── README.md
```

---

## Tech Stack

| Layer     | Technology                              |
|-----------|-----------------------------------------|
| Backend   | Python 3.11+, FastAPI, dnspython        |
| Server    | uvicorn                                 |
| Frontend  | Plain HTML + CSS + Vanilla JS (no framework) |
| Templates | Jinja2 (report generation)              |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Serves the dashboard |
| `POST` | `/api/analyze` | Runs a DNS analysis. Body: `{ "domain": "example.com" }` |
| `GET`  | `/api/report/{domain}` | Downloads a standalone HTML report |

---

## Out of Scope (v2 ideas)

- SPF / DKIM / DMARC validation
- DNSSEC checks
- Wildcard DNS detection
- Subdomain takeover detection
- Scan history / database
- User accounts / auth
- PDF export
