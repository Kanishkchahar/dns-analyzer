# DNS Analyzer v2 — Security Posture Cockpit Edition

A high-performance, asynchronous DNS and web security posture scanner. Enter a domain or full URL to review DNS records (including CAA), SPF / DMARC / DKIM, DNSSEC, MTA-STS and TLS-RPT, TLS certificates, browser security headers, passive Certificate Transparency subdomains, and more. The dashboard includes optional scoped path discovery, scan coverage and browser-local history, CSV and report exports, and actionable findings.

The dashboard uses the full browser width. Current releases also include direct-authority AXFR and nameserver checks, wildcard DNS detection, a command-line scanner, finding explanations, provider-specific remediation guidance, and a cached grade badge endpoint. See [Current scope and limitations](#current-scope-and-limitations) for checks that are not implemented yet.

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
# Pull the versioned release image
docker pull kanishkchahar/dns-analyzer:v2.1.0

# Run container on port 8000
docker run -d --name dns-analyzer-v2 --restart unless-stopped -p 8000:8000 kanishkchahar/dns-analyzer:v2.1.0
```

#### Option B: Build & Run Locally

```bash
# Build the multi-stage production image (the test stage runs during the build)
docker build -t dns-analyzer:v2.1.0 -t dns-analyzer:v2 .

# Run container on port 8000
docker run -d --name dns-analyzer-v2 --restart unless-stopped -p 8000:8000 dns-analyzer:v2.1.0
```

#### Container Management:

```bash
# View real-time container logs
docker logs -f dns-analyzer-v2

# Run automated tests inside the container
docker run --rm dns-analyzer:v2.1.0 pytest -v

# Stop and remove the container
docker stop dns-analyzer-v2 && docker rm dns-analyzer-v2
```

---

## ⚡ Key Architecture & Features

### 1. Executive Security Posture Cockpit (Asymmetric Bento Grid)
- **DNS and Email Score Ring**: Animated SVG ring showing the DNS and email posture score (**A+ to F**, **0–100**). It is not an all-up web security score: TLS, MTA-STS, TLS-RPT, and BIMI findings are reported separately and do not affect it. A confirmed AXFR caps the score at 39 (grade F); inconclusive DNSSEC receives no DNSSEC points and is listed as inconclusive.
- **Executive Posture Subtitle & Filter Badges**: Real-time status headlines (`All Systems Authenticated & Safe`, `Warnings — Review Advised`, or `Critical Issues Detected`) with one-click filtering by severity (Errors, Warnings, Info).
- **Four 2×2 Quadrants (Zero Text Truncation)**:
  - **🌐 DNS Infrastructure**: A/AAAA record presence, NS count, and SOA data. The analyzer does not test whether the web service accepts connections over both IP versions.
  - **✉️ Email Authentication**: Phishing defense posture, SPF policy, DMARC enforcement level, and DKIM selectors.
  - **🔐 Cryptography & Takeover**: DNSSEC key algorithms, DS delegation status, and dangling CNAME checks.
  - **🔧 DNS Remediation Drafts**: Copy-paste record suggestions ready for review. The tool does not apply changes to providers.

### 2. Comprehensive Scan Suite
- **8 DNS Record Types**: A, AAAA, MX, NS, TXT, CNAME, SOA, and CAA queried concurrently. CAA policy inherited from parent labels is shown where applicable.
- **Authoritative Zone Apex Discovery (RFC 1034/2181)**: Discovers the authoritative zone apex before checking NS, SOA, and DNSSEC, preventing false alarms when analyzing subdomains (e.g. `mail.example.com`).
- **10 DNS Infrastructure Checks**: A/AAAA record resolution (not a connection test), NS redundancy and hostname resolution, MX hostname resolution, CNAME coexistence conflicts (RFC 1034), SOA refresh/retry sanity (RFC 1912), TTL bounds, and CAA policy.
- **SPF Deep Audit (RFC 7208)**: Syntax validation, recursion tree traversal against the 10-lookup limit, `+all` spoof detection, and automatic CIDR flattening.
- **DMARC Security Engine (RFC 7489)**: Evaluates policy enforcement (`none` → `quarantine` → `reject`), organizational domain fallback discovery, alignment flags (`adkim`, `aspf`), and aggregate reporting (`rua`).
- **DKIM Multi-Selector Scanner (RFC 6376)**: Checks common selectors and lets users supply up to 20 additional selector names. Results include public key metadata and distinguish missing records from inconclusive DNS lookups.
- **Mail Transport Security**: Checks `_mta-sts` and `_smtp._tls` DNS records, safely retrieves a published MTA-STS policy file, and reports TLS-RPT destinations. It does not send email.
- **Subdomain Takeover Fingerprint Checks**: Uses a separate catalog of 10 service patterns (GitHub Pages, S3 and S3 website endpoints, Heroku, Shopify, Zendesk, Ghost, Surge, Vercel, and Azure App Service). Only a matching bounded HTTP response is labeled confirmed; DNS-only evidence is a warning-level candidate. Patterns have not all been independently verified against live provider accounts, so manually confirm results.
- **DNSSEC delegation check (RFC 4033–4035)**: Inspects DNSKEY and parent DS records, key algorithms, and DS-to-DNSKEY matches. This is a partial check, not complete DNSSEC signature or trust-chain validation.
- **Authoritative DNS posture**: Attempts TCP AXFR against listed nameservers (reports only record counts), probes random labels for wildcard DNS, and directly compares nameserver SOA serials and NS answers.
- **TLS & HTTPS Security Audit**: Certificate validity, negotiated TLS, HTTPS redirection, HSTS, CSP risk notes, Permissions-Policy, cross-origin isolation headers, and cookie security flags. An `OPTIONS` request reports advertised methods only; the scanner does not send write-method probes.
- **Passive Subdomain Inventory**: Queries Certificate Transparency (CT) logs for publicly logged hostnames, resolves discovered names, checks CNAME takeover signatures, labels wildcard-only results, marks risky labels, records available first-seen dates, sorts by risk, and provides CSV export.
- **Optional Common Path Scan**: Checks a bounded set of common web paths and reads same-origin `robots.txt` and sitemap references. It does not crawl directories; discovered paths are labeled for review and are not accessed automatically beyond the bounded checks.
- **Scan Coverage & Change History**: Shows completed, partial, blocked, and optional checks. The browser can compare DNS, CT, TLS certificate, and optional path results with earlier scans stored locally.
- **Scoped Network Inventory & Port Verification**: Nmap-style scoped target resolution and safe port auditing with strict SSRF guardrails (blocking RFC 1918 private subnets `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and loopback `127.0.0.0/8`).
- **BIMI Brand Certification (RFC 8617)**: Verifies SVG brand logo publication and VMC eligibility for inbox verification in Gmail, Apple Mail, and Yahoo Mail.

### 3. Actionable Remediation & Multi-Format Export
- **DNS Fix Generator**: Copy-paste draft records with provider guidance for Cloudflare, AWS Route 53, Namecheap, Hostinger, BigRock, Google Cloud DNS, and Azure DNS. CLI examples are included where supported. Review suggestions before applying them yourself.
- **Re-check after a fix**: Runs a fresh scan, compares findings, and shows the observed record TTL as a cache-delay guide.
- **Finding catalog**: Gives findings stable codes and shared plain-language explanations, attacker context, technical notes, and fixes.
- **Export BIND Zone File**: Generates compliant `.zone` configuration files with one click.
- **Standalone Offline Report**: Single-file HTML report with inlined styles that opens without a web server.
- **CLI `dig` Terminal Simulation**: Toggle between visual card view and an interactive colorized terminal output (`dig +noall +answer`).
- **One-Click Markdown & JSON Export**: Instant copyable Markdown summary tables for GitHub/Slack and raw JSON exports for automation.
- **Command-line scanner**: `dns-analyzer example.com` runs the same scan pipeline as the API; supports JSON and minimum-grade gates.
- **Grade badge API**: `/api/badge/{domain}` serves an SVG badge only while a matching in-memory scan result is fresh (60-second cache).

The overall dashboard score is labeled **DNS and email posture**. TLS findings do not affect that score; mail transport and BIMI checks are also shown separately.

### CLI

The setup script installs the `dns-analyzer` command into `venv/`:

```bash
bash run.sh --setup-only
./venv/bin/dns-analyzer example.com
./venv/bin/dns-analyzer example.com --json
./venv/bin/dns-analyzer example.com --min-grade B
```

Exit codes: `0` success, `1` invalid input or tool failure, `2` grade below `--min-grade`, and `3` when the scan has error-level findings. Error findings take precedence over the grade threshold.

### Current scope and limitations

- DNSSEC currently verifies DS-to-DNSKEY delegation matching. It does not perform cryptographic RRSIG validation or display a complete root/TLD/domain trust chain.
- AXFR results expose server status and record counts only; record contents are not returned. Network checks are time-bounded and use public nameserver addresses.
- Takeover detection uses the signatures shipped with this repository; it is not an exhaustive service catalog and automated fingerprints can become stale.
- The catalog is seeded from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) and records its CC BY 4.0 attribution. No live-verification date is recorded for the shipped entries; review them before relying on a match.
- Scan history remains in browser local storage. There is no server-side scheduler, verified-account system, email alerting, or webhook monitoring.
- The API does not yet provide the planned bulk full-analysis workflow. The existing scoped network list scan is a separate diagnostic.
- RDAP domain-expiry and dangling-nameserver registration checks are not implemented yet.
- Grade badges are process-local and disappear when the server restarts or its scan cache expires. They are not backed by a persistent scan database.
- `run_full_scan` in `app.main` is the shared Python scan entry point used by the API and CLI; it returns the application's Pydantic response model.
- TLS/HTTP, CT, DNS, and third-party responses can fail or vary. The coverage panel reports checks that are inconclusive or unavailable; results are not a guarantee of security.

### Comparison with related tools

This is a scope comparison from each project's published description, not a benchmark or replacement claim. Feature descriptions can change; checked 2026-11-07.

| Tool | Main focus | How its scope differs |
|---|---|---|
| DNS Analyzer | Browser dashboard and Python CLI for DNS, email authentication, selected TLS/web checks, CT inventory, and remediation drafts | Broad dashboard workflow; DNSSEC currently checks DS-to-DNSKEY matching but not the complete signature chain |
| [DNSViz](https://dnsviz.net/) | Visual analysis of DNSSEC authentication and DNS resolution paths | More specialized DNSSEC chain visualization and troubleshooting |
| [Zonemaster](https://zonemaster.ripe.net/) | DNS delegation and zone-quality testing, including DNSSEC and nameserver behavior | Deeper authoritative DNS testing, including parent/child delegation and server connectivity |
| [dnsight](https://pypi.org/project/dnsight/) | Python CLI and SDK for DNS and email-authentication audits | Developer-oriented CLI/SDK and structured output; its package documentation does not describe a browser-first dashboard |
| [gossan-dns](https://docs.rs/crate/gossan-dns/latest/) | Rust DNS audit crate for email records, AXFR, CAA, posture, and takeover signatures | Library/crate integration focus; its published feature set includes broader takeover fingerprint coverage |

No hosted demo URL or dashboard screenshot is configured in this repository yet. Run `bash run.sh` to inspect the current interface locally.

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
│   ├── cli.py                # Installed command-line entry point
│   ├── dns_posture.py        # AXFR, wildcard, and direct NS consistency checks
│   ├── finding_catalog.py    # Stable finding codes and explanations
│   └── provider_templates.py # DNS provider guidance and TXT formatting
├── static/                  # Browser UI (HTML, CSS, and JavaScript)
├── tests/                   # Unit, integration, and API tests
├── docs/
│   └── PRESENTATION.md      # Demo guide, scan catalog, and viva notes
├── README.md                # Setup, features, API, and deployment guide
├── Dockerfile               # Multi-stage image build and test gate
├── .dockerignore            # Files excluded from Docker build context
├── pytest.ini               # Pytest discovery and warning configuration
├── requirements.txt         # Python runtime and test dependencies
├── pyproject.toml            # Package metadata and dns-analyzer CLI entry point
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

*(Also accepts a URL such as `https://example.com/path?query=1`; the hostname is extracted.)*

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
    { "severity": "info", "record_type": "A", "message": "Domain resolves to an IPv4 address." }
  ],
  "summary": { "errors": 0, "warnings": 0, "info": 1 },
  "email_auth": {
    "spf": { "raw": "v=spf1 -all", "all_mechanism": "-all" },
    "spf_lookups": { "total_lookups": 0, "limit": 10, "over_limit": false },
    "dmarc": { "raw": "v=DMARC1; p=reject;", "policy": "reject", "pct": 100 },
    "dkim": { "has_dkim": true, "selectors_found": [] },
    "score": { "score": 100, "grade": "A+", "label": "Optimal" }
  },
  "domain_score": { "score": 100, "grade": "A+", "scope": "DNS and email posture (TLS, MTA-STS, TLS-RPT, and BIMI are reported separately)", "inconclusive_checks": [] },
  "security": {
    "dnssec": { "status": "delegation_match_verified", "dnskey_count": 2, "ds_count": 2 },
    "takeover": { "vulnerable": false, "status": "safe" },
    "bimi": { "has_bimi": false, "dmarc_eligible": true }
  },
  "remediation": [],
  "bind_zone_snippet": "; BIND Zone file ..."
}
```

### 2. Download Standalone Offline Report
`GET /api/report/{domain}` returns a self-contained `.html` file with embedded CSS, viewable offline.

### 3. Grade badge
`GET /api/badge/{domain}` returns an SVG badge only while a recent scan exists in this server process. It returns `404` after the in-memory scan expires or when no scan exists.

### 4. Run a Bounded Common Path Scan
`POST /api/network/path-scan`

```json
{ "targets": ["example.com"] }
```

Accepts up to five hostnames or public IPs. Checks a fixed list of common paths and same-origin paths advertised by `robots.txt` or sitemap files. This is not a recursive directory crawler.

### 5. Check Custom DKIM Selectors
`POST /api/email/dkim-selectors`

```json
{ "domain": "example.com", "selectors": ["selector3", "mail2026"] }
```

Accepts 1–20 selector names for the specified domain.

### 6. Scoped Network Tools
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
| **RFC 5321** | Simple Mail Transfer Protocol (SMTP) | MX existence and mail host address resolution |
| **RFC 7208** | Sender Policy Framework (SPF) | Authorized senders, syntax qualifiers, 10-lookup limit |
| **RFC 7489** | DMARC Domain-based Message Authentication | Reject/quarantine enforcement, alignment, aggregate reports |
| **RFC 6376** | DomainKeys Identified Mail (DKIM) | Selector discovery, public key extraction, cryptographic integrity |
| **RFC 4033 / 4034 / 4035** | DNS Security Extensions (DNSSEC) | DNSKEY inspection and DS-to-DNSKEY delegation matching |
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
- `test_analyzer.py`: 10 DNS infrastructure checks and summary generation
- `test_spf.py`: SPF parsing, lookup recursion tracking, and CIDR record flattening
- `test_email_auth.py`: DMARC policy grading, DKIM selectors, and weighted health scoring
- `test_dnssec.py`: DNSKEY/DS delegation status and matching
- `test_dns_posture.py`: Count-only AXFR, wildcard DNS, and authoritative NS consistency checks
- `test_dns_posture.py`: AXFR count-only behavior, wildcard detection, and direct-authority consistency
- `test_cli.py`: Human/JSON output, grade threshold, and exit codes
- `test_provider_templates.py`: TXT chunk formatting and provider remediation guidance
- `test_takeover.py`: Subdomain takeover fingerprints and dangling CNAME detection
- `test_bimi.py`: BIMI logo parsing, VMC verification, and DMARC eligibility
- `test_network_scan.py`: Scope verification, SSRF blocking, and active port scan policies
- `test_tls_check.py`: Certificate auditing, SAN wildcard validation, and IP rebinding protection
- `test_remediation.py`: Copy-paste draft generator and BIND zone file creation
- `test_report.py`: Standalone offline HTML report rendering
- `test_resolver.py`: Concurrent asynchronous DNS resolution
- `test_zone_discovery.py`: Zone apex detection and delegated SOA handling
- `test_api.py`: FastAPI endpoints and HTTP contract validation
- `test_models.py`: Domain validation regex and Pydantic schemas

---

## 📄 License

MIT License. Designed and engineered for high-concurrency DNS diagnostics, infrastructure auditing, and modern cybersecurity resilience.
