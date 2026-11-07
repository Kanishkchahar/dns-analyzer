# DNS Analyzer v2 — Security Posture Cockpit Edition

A high-performance, asynchronous DNS and web security posture scanner. Enter a domain or full URL to review DNS records (including CAA), SPF / DMARC / DKIM, DNSSEC, MTA-STS and TLS-RPT, TLS certificates, browser security headers, passive Certificate Transparency subdomains, and more. The dashboard includes optional scoped path discovery, scan coverage and browser-local history, CSV and report exports, and actionable findings.

---

## 🚀 Quick Start

### One-Command Setup & Launch (Recommended)

```bash
bash run.sh
```

This all-in-one runner automatically:
- Verifies Python 3.11+ (supports Python 3.11, 3.12, 3.13, 3.14)
- Verifies or self-heals the local `venv/` virtual environment
- Installs or updates dependencies from `requirements.txt`
- Starts the production server on **http://127.0.0.1:8000** with auto-reload

#### Custom Port

```bash
bash run.sh 9000
```

#### Setup Only (Prepare Environment Without Starting Server)

```bash
bash run.sh --setup-only
```

#### Automated Test Suite

```bash
bash run.sh --test
# Or run pytest directly in venv:
./venv/bin/pytest -v
```

---

### Run with Docker

#### Option A: Pull & Run Directly from Docker Hub

```bash
# Pull the verified v2 release image
docker pull kanishkchahar/dns-analyzer:v2

# Run container on port 8000
docker run -d --name dns-analyzer-v2 --restart unless-stopped -p 8000:8000 kanishkchahar/dns-analyzer:v2
```

#### Option B: Build & Run Locally

```bash
# Build the multi-stage production image (the test stage runs during the build)
docker build -t dns-analyzer:v2 .

# Run container on port 8000
docker run -d --name dns-analyzer-v2 --restart unless-stopped -p 8000:8000 dns-analyzer:v2
```

#### Container Management:

```bash
# View real-time container logs
docker logs -f dns-analyzer-v2

# Run automated tests inside the container
docker run --rm dns-analyzer:v2 pytest -v

# Stop and remove the container
docker stop dns-analyzer-v2 && docker rm dns-analyzer-v2
```

---

## ⚡ Key Architecture & Features

### 1. Executive Security Posture Cockpit (Asymmetric Bento Grid)
- **Dominant Score Ring Hero (Left Column)**: Animated SVG circular health ring translating DNS & email posture into an immediate letter grade (**A+ to F**) and numerical score (**0–100**).
- **Executive Posture Subtitle & Filter Badges**: Real-time status headlines (`All Systems Authenticated & Safe`, `Warnings — Review Advised`, or `Critical Issues Detected`) with one-click filtering by severity (Errors, Warnings, Info).
- **Four 2×2 Quadrants (Zero Text Truncation)**:
  - **🌐 DNS Infrastructure**: Dual-Stack status (IPv4 / IPv6), redundant NS count, and SOA authority.
  - **✉️ Email Authentication**: Phishing defense posture, SPF policy, DMARC enforcement level, and DKIM selectors.
  - **🔐 Cryptography & Takeover**: DNSSEC key algorithms, DS delegation status, and dangling CNAME checks.
  - **🔧 1-Click Remediation**: Number of copy-paste zone fixes ready with direct jump navigation.

### 2. Comprehensive Scan Suite
- **8 DNS Record Types**: A, AAAA, MX, NS, TXT, CNAME, SOA, and CAA queried concurrently. CAA policy inherited from parent labels is shown where applicable.
- **Authoritative Zone Apex Discovery (RFC 1034/2181)**: Discovers the authoritative zone apex before checking NS, SOA, and DNSSEC, preventing false alarms when analyzing subdomains (e.g. `mail.example.com`).
- **9 RFC Infrastructure Rules**: Dual-stack reachability, NS redundancy, NS/MX IP resolution, CNAME coexistence conflicts (RFC 1034), SOA refresh/retry sanity (RFC 1912), and TTL bounds.
- **SPF Deep Audit (RFC 7208)**: Syntax validation, recursion tree traversal against the 10-lookup limit, `+all` spoof detection, and automatic CIDR flattening.
- **DMARC Security Engine (RFC 7489)**: Evaluates policy enforcement (`none` → `quarantine` → `reject`), organizational domain fallback discovery, alignment flags (`adkim`, `aspf`), and aggregate reporting (`rua`).
- **DKIM Multi-Selector Scanner (RFC 6376)**: Checks common selectors and lets users supply up to 20 additional selector names. Results include public key metadata and distinguish missing records from inconclusive DNS lookups.
- **Mail Transport Security**: Checks `_mta-sts` and `_smtp._tls` DNS records, safely retrieves a published MTA-STS policy file, and reports TLS-RPT destinations. It does not send email.
- **Subdomain Takeover Defense (CVE Threat Hunting)**: Detects dangling CNAMEs pointing to abandoned cloud endpoints (AWS S3, GitHub Pages, Heroku, Shopify, Zendesk, Surge, Azure, Vercel) before attackers hijack them.
- **DNSSEC Chain-of-Trust (RFC 4033–4035)**: Audits Key Signing Keys (KSK), Zone Signing Keys (ZSK), algorithms (ECDSA, Ed25519, RSA), and parent registry DS records to guarantee immunity against DNS cache poisoning (Kaminsky attacks).
- **TLS & HTTPS Security Audit**: Certificate validity, negotiated TLS, HTTPS redirection, HSTS, CSP risk notes, Permissions-Policy, cross-origin isolation headers, and cookie security flags. An `OPTIONS` request reports advertised methods only; the scanner does not send write-method probes.
- **Passive Subdomain Inventory**: Queries Certificate Transparency (CT) logs for publicly logged hostnames, checks discovered DNS pointers, and provides CSV export.
- **Optional Common Path Scan**: Checks a bounded set of common web paths and reads same-origin `robots.txt` and sitemap references. It does not crawl directories; discovered paths are labeled for review and are not accessed automatically beyond the bounded checks.
- **Scan Coverage & Change History**: Shows completed, partial, blocked, and optional checks. The browser can compare DNS, CT, TLS certificate, and optional path results with earlier scans stored locally.
- **Scoped Network Inventory & Port Verification**: Nmap-style scoped target resolution and safe port auditing with strict SSRF guardrails (blocking RFC 1918 private subnets `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and loopback `127.0.0.0/8`).
- **BIMI Brand Certification (RFC 8617)**: Verifies SVG brand logo publication and VMC eligibility for inbox verification in Gmail, Apple Mail, and Yahoo Mail.

### 3. Actionable Remediation & Multi-Format Export
- **1-Click DNS Fix Generator**: Tailored copy-paste records for Cloudflare, AWS Route 53, and GoDaddy.
- **Export BIND Zone File**: Generates compliant `.zone` configuration files with one click.
- **Standalone Offline Report**: Single-file HTML report with inlined styles that opens without a web server.
- **CLI `dig` Terminal Simulation**: Toggle between visual card view and an interactive colorized terminal output (`dig +noall +answer`).
- **One-Click Markdown & JSON Export**: Instant copyable Markdown summary tables for GitHub/Slack and raw JSON exports for automation.

---

## ⌨️ Radical Ease of Access & Shortcuts

| Shortcut | Action |
|:---:|---|
| <kbd>/</kbd> | Focus the domain search bar from anywhere |
| <kbd>Enter</kbd> | Run concurrent analysis |
| <kbd>1</kbd> – <kbd>4</kbd> | Analyze sample domains (`google.com`, `cloudflare.com`, etc.) |
| <kbd>f</kbd> | Cycle findings severity filters (All → Errors → Warnings → Info) |
| <kbd>v</kbd> | Toggle between Record Cards and CLI `dig` Terminal view |
| <kbd>c</kbd> | Copy shareable scan link (`?domain=...`) |
| <kbd>m</kbd> | Copy formatted Markdown summary for GitHub or Slack |
| <kbd>j</kbd> | Export complete raw scan JSON data |
| <kbd>d</kbd> | Download standalone offline HTML diagnostic report |
| <kbd>z</kbd> | Download copy-paste BIND zone file |
| <kbd>?</kbd> | Open Keyboard Shortcuts & Accessibility Modal |
| <kbd>Esc</kbd> | Dismiss modals, error banners, or clear search queries |

---

## 📁 Project Structure

```
dns-analyzer/
├── app/                     # FastAPI backend, scans, models, and report builder
├── static/                  # Browser UI (HTML, CSS, and JavaScript)
├── tests/                   # Unit, integration, and API tests
├── docs/
│   └── PRESENTATION.md      # Demo guide, scan catalog, and viva notes
├── README.md                # Setup, features, API, and deployment guide
├── Dockerfile               # Multi-stage image build and test gate
├── .dockerignore            # Files excluded from Docker build context
├── pytest.ini               # Pytest discovery and warning configuration
├── requirements.txt         # Python runtime and test dependencies
└── run.sh                   # Local setup, test, Docker, and server commands
```

The local `venv/` (or `.venv/`) is generated by the setup script and ignored by Git; it is not part of the application source tree.

---

## 🔌 API Reference

### 1. Run Domain Analysis
`POST /api/analyze`

**Request Body:**
```json
{
  "domain": "example.com"
}
```
*(Also accepts dirty URLs such as `https://example.com/path?query=1` — the hostname is auto-extracted).*

**Response Schema (Sample):**
```json
{
  "domain": "example.com",
  "scan_timestamp": "2026-11-07 12:00:00 UTC",
  "records": {
    "A": { "status": "ok", "ttl": 300, "records": ["93.184.215.14"] },
    "AAAA": { "status": "ok", "ttl": 300, "records": ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"] },
    "MX": { "status": "no_records", "ttl": null, "records": [] },
    "NS": { "status": "ok", "ttl": 86400, "records": [{ "host": "a.iana-servers.net", "resolves": true }] },
    "TXT": { "status": "ok", "ttl": 3600, "records": ["v=spf1 -all"] },
    "CNAME": { "status": "no_records", "ttl": null, "records": [] },
    "SOA": { "status": "ok", "ttl": 3600, "records": { "mname": "ns.icann.org", "serial": 2024010101 } }
  },
  "findings": [
    { "severity": "info", "record_type": "A", "message": "Domain resolves to 1 IPv4 address (Dual-Stack available)." }
  ],
  "summary": { "errors": 0, "warnings": 0, "info": 1 },
  "email_auth": {
    "spf": { "raw": "v=spf1 -all", "all_mechanism": "-all" },
    "spf_lookups": { "total_lookups": 0, "limit": 10, "over_limit": false },
    "dmarc": { "raw": "v=DMARC1; p=reject;", "policy": "reject", "pct": 100 },
    "dkim": { "has_dkim": true, "selectors_found": [] },
    "score": { "score": 100, "grade": "A+", "label": "Optimal" }
  },
  "security": {
    "dnssec": { "status": "secured", "dnskey_count": 2, "ds_count": 2 },
    "takeover": { "vulnerable": false, "status": "safe" },
    "bimi": { "has_bimi": false, "dmarc_eligible": true }
  },
  "remediation": [],
  "bind_zone_snippet": "; BIND Zone file ..."
}
```

### 2. Download Standalone Offline Report
`GET /api/report/{domain}`

Returns a self-contained `.html` file with embedded CSS, fully viewable offline.

### 3. Run a Bounded Common Path Scan
`POST /api/network/path-scan`

```json
{ "targets": ["example.com"] }
```

Accepts up to five hostnames or public IPs. Checks a fixed list of common paths and same-origin paths advertised by `robots.txt` or sitemap files. This is not a recursive directory crawler.

### 4. Check Custom DKIM Selectors
`POST /api/email/dkim-selectors`

```json
{ "domain": "example.com", "selectors": ["selector3", "mail2026"] }
```

Accepts 1–20 selector names for the specified domain.

### 5. Scoped Network Tools
`POST /api/network/list-scan` resolves target scope. `POST /api/network/port-scan` performs standard-port checks only when authorization and server policy permit them. Active port probing is opt-in and remains subject to the configured allowlist and SSRF controls.

---

## ⚙️ Deployment & Environment Configuration

The application is configured via environment variables:

| Variable | Default | Purpose / Security Guard |
|:---|:---|:---|
| `ENABLE_ACTIVE_PORT_SCAN` | `false` | Master toggle for active TCP port probes. Requires explicit server policy (`PORT_SCAN_API_KEY` and/or `PORT_SCAN_ALLOWED_DOMAINS`) before probes are permitted. |
| `PORT_SCAN_API_KEY` | *(unset)* | Shared secret token required for authenticating active port scan requests via `auth_token` or `Authorization: Bearer <key>` header. |
| `PORT_SCAN_ALLOWED_DOMAINS`| *(unset)* | Comma-separated list of approved target domains/hostnames for active port scans (e.g. `example.com, target.org`). |
| `TRUST_REVERSE_PROXY` | `false` | Inspects `X-Forwarded-For` for client rate limiting. **Security Notice**: Only enable this behind an upstream reverse proxy (e.g. Nginx, Cloudflare) that strips or overwrites untrusted incoming `X-Forwarded-For` headers from external clients to prevent identity spoofing. |
| `TESTING` | `false` | Internal flag used by test harnesses to bypass artificial IP rate limits. |

#### Docker Multi-Stage Testing Note
The [`Dockerfile`](Dockerfile) uses a multi-stage build where the final production runtime stage depends on the test verification stage (`COPY --from=test`). Building the image automatically executes `pytest -v` inside the container. You can also explicitly run the test stage using:
```bash
docker build --target test -t dns-analyzer-test .
```

---

## 📜 RFC Standards Referenced

| RFC | Specification | Diagnostic Scope |
|:---|:---|:---|
| **RFC 1034 / 1035** | Domain System Concepts & Facility | Core record structure, CNAME exclusivity, NS delegation |
| **RFC 1912 / 2182** | DNS Operational Guidelines | Authoritative server redundancy, SOA refresh/retry sanity |
| **RFC 5321** | Simple Mail Transfer Protocol (SMTP) | MX existence, mail host reachability, delivery guarantee |
| **RFC 7208** | Sender Policy Framework (SPF) | Authorized senders, syntax qualifiers, 10-lookup limit |
| **RFC 7489** | DMARC Domain-based Message Authentication | Reject/quarantine enforcement, alignment, aggregate reports |
| **RFC 6376** | DomainKeys Identified Mail (DKIM) | Selector discovery, public key extraction, cryptographic integrity |
| **RFC 4033 / 4034 / 4035** | DNS Security Extensions (DNSSEC) | RRSIG validation, DNSKEY verification, DS parent trust delegation |
| **RFC 8617** | Brand Indicators for Message Identification (BIMI) | Official logo presentation in verified client inboxes |
| **RFC 8659** | DNS Certification Authority Authorization (CAA) | Certificate issuance policy and inherited parent records |
| **RFC 8461** | SMTP MTA Strict Transport Security (MTA-STS) | Published mail transport policy and HTTPS policy-file checks |
| **RFC 8460** | SMTP TLS Reporting (TLS-RPT) | DNS reporting destination configuration |

---

## 🧪 Testing

The repository includes unit and integration tests runnable with:

```bash
# Run via all-in-one runner:
bash run.sh --test

# Or run pytest directly:
./venv/bin/pytest -v
```

Coverage spans:
- `test_analyzer.py`: 9 RFC infrastructure checks and summary generation
- `test_spf.py`: SPF parsing, lookup recursion tracking, and CIDR record flattening
- `test_email_auth.py`: DMARC policy grading, DKIM selectors, and weighted health scoring
- `test_dnssec.py`: Cryptographic chain-of-trust, algorithm detection, and DS validation
- `test_takeover.py`: Subdomain takeover fingerprints and dangling CNAME detection
- `test_bimi.py`: BIMI logo parsing, VMC verification, and DMARC eligibility
- `test_network_scan.py`: Scope verification, SSRF blocking, and active port scan policies
- `test_tls_check.py`: Certificate auditing, SAN wildcard validation, and IP rebinding protection
- `test_remediation.py`: 1-Click fix generator and BIND zone file creation
- `test_report.py`: Standalone offline HTML report rendering
- `test_resolver.py`: Concurrent asynchronous DNS resolution
- `test_zone_discovery.py`: Zone apex detection and delegated SOA handling
- `test_api.py`: FastAPI endpoints and HTTP contract validation
- `test_models.py`: Domain validation regex and Pydantic schemas

---

## 📄 License

MIT License. Designed and engineered for high-concurrency DNS diagnostics, infrastructure auditing, and modern cybersecurity resilience.
