# DNS Analyzer 2.2.0 — Security Posture Cockpit Edition

A high-performance, asynchronous DNS and web security posture scanner. Enter a domain or full URL to review DNS records (including CAA), SPF / DMARC / DKIM, DNSSEC, MTA-STS and TLS-RPT, TLS certificates, browser security headers, passive Certificate Transparency subdomains, and more. The dashboard includes optional scoped path discovery, scan coverage and browser-local history, CSV and report exports, and actionable findings.

The dashboard uses the full browser width. Current releases also include direct-authority AXFR and nameserver checks, wildcard DNS detection, a command-line scanner, finding explanations, provider-specific remediation guidance, and a cached grade badge endpoint. See [Current scope and limitations](#current-scope-and-limitations) for checks that are not implemented yet.

---

## 🚀 Quick Start

### One-Command Setup & Launch (Recommended)

```bash
bash run.sh
```

This all-in-one runner automatically:
- Requires Python 3.11 or newer; the Docker image defaults to Python 3.11.
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
docker pull kanishkchahar/dns-analyzer:v2.2.0

# Run container on port 8000
docker run -d --name dns-analyzer-v2 --restart unless-stopped -p 8000:8000 kanishkchahar/dns-analyzer:v2.2.0
```

#### Option B: Build & Run Locally

```bash
# Build the multi-stage production image (the test stage runs during the build)
docker build -t dns-analyzer:v2.2.0 -t dns-analyzer:v2 .

# Run container on port 8000
docker run -d --name dns-analyzer-v2 --restart unless-stopped -p 8000:8000 dns-analyzer:v2.2.0
```

#### Container Management:

```bash
# View real-time container logs
docker logs -f dns-analyzer-v2

# Run automated tests inside the container
docker run --rm dns-analyzer:v2.2.0 pytest -v

# Stop and remove the container
docker stop dns-analyzer-v2 && docker rm dns-analyzer-v2
```

---

## ⚡ Key Architecture & Features

### 1. Executive Security Posture Cockpit (Asymmetric Bento Grid)
- **Weighted Posture Score (2.2.0)**: The score uses DNS infrastructure (20), email authentication (25), DNSSEC (20), takeover evidence (15), TLS/web (10), mail transport (5), and DNS posture (5). Not-applicable and wholly inconclusive factors are excluded; remaining weights are normalized to 100. Partial factors score only completed checks. The breakdown lists excluded factors and the headline reports `based on X of Y factors`. Excluded weight above 30% marks the grade provisional (`(incomplete)`). Successful AXFR caps the score at 54; confirmed takeover and bogus DNSSEC each cap it at 39, with reasons shown.
- **Takeover deduction**: For the 15-point factor, `safe` earns 15 (0 deducted), `candidate` earns 6.75 (8.25 deducted), and `confirmed` earns 0 (15 deducted and the score is capped at 39). Candidate deduction is `15 × (1 − 0.45) = 8.25`: candidate evidence earns 45% of factor points and deducts 55%. `inconclusive` and `not_applicable` are excluded; inconclusive never triggers a cap.
- **Version 2.2.0** changes score normalization and provisional-grade reporting. Grades and `--min-grade` results may differ from earlier versions.
- See [CHANGELOG.md](CHANGELOG.md) for the 2.2.0 release notes.
- **Executive Posture Subtitle & Filter Badges**: Real-time status headlines (`All Systems Authenticated & Safe`, `Warnings — Review Advised`, or `Critical Issues Detected`) with one-click filtering by severity (Errors, Warnings, Info).
- **Four 2×2 Quadrants (Zero Text Truncation)**:
  - **🌐 DNS Infrastructure**: A/AAAA record presence, NS count, and SOA data. The analyzer does not test whether the web service accepts connections over both IP versions.
  - **✉️ Email Authentication**: Phishing defense posture, SPF policy, DMARC enforcement level, and DKIM selectors.
  - **🔐 Cryptography & Takeover**: DNSSEC key algorithms, DS delegation status, and dangling CNAME checks.
  - **🔧 DNS Remediation Drafts**: Copy-paste record suggestions ready for review. The tool does not apply changes to providers.

### 2. Comprehensive Scan Suite
- **8 DNS Record Types**: A, AAAA, MX, NS, TXT, CNAME, SOA, and CAA queried concurrently. CAA policy inherited from parent labels is shown where applicable.
- **Authoritative Zone Apex Discovery (RFC 1034/2181)**: Discovers the authoritative zone apex before checking NS, SOA, and DNSSEC, preventing false alarms when analyzing subdomains (e.g. `mail.example.com`).
- **DNS Infrastructure Checks**: A/AAAA record presence (not a connection test), NS redundancy and hostname resolution, MX hostname resolution, CNAME coexistence conflicts (RFC 1034), SOA refresh/retry sanity (RFC 1912), TTL bounds, and CAA policy.
- **SPF Deep Audit (RFC 7208)**: Syntax validation, recursion tree traversal against the 10-lookup limit, `+all` spoof detection, and automatic CIDR flattening.
- **DMARC Security Engine (RFC 7489)**: Evaluates policy enforcement (`none` → `quarantine` → `reject`), organizational domain fallback discovery, alignment flags (`adkim`, `aspf`), and aggregate reporting (`rua`).
- **DKIM Multi-Selector Scanner (RFC 6376)**: Checks common selectors and lets users supply up to 20 additional selector names. Results include public key metadata and distinguish missing records from inconclusive DNS lookups.
- **Mail Transport Security**: Checks `_mta-sts` and `_smtp._tls` DNS records, safely retrieves a published MTA-STS policy file, and reports TLS-RPT destinations. It does not send email.
- **Subdomain Takeover Fingerprint Checks**: Uses a separate catalog of 10 service patterns (GitHub Pages, S3 and S3 website endpoints, Heroku, Shopify, Zendesk, Ghost, Surge, Vercel, and Azure App Service). Every shipped entry is unverified and has NXDOMAIN confirmation disabled, so both page-text matches and DNS-only evidence are candidates. Only entries explicitly verified in the data file can produce confirmation; even then the scanner does not prove provider-side claimability.
- **DNSSEC chain validation (RFC 4033–4035)**: Requests DNSSEC data (DO), validates DNSKEY, DS, and zone SOA signatures from the root anchor through the zone, and reports secure, insecure, bogus, or indeterminate. Unsupported/failed retrieval is indeterminate; DS absence is labeled `insecure (denial not validated)` because denial proofs are not validated. NSEC/NSEC3 denial details remain informational.
- **Authoritative DNS posture**: Attempts TCP AXFR against listed nameservers (reports only record counts), probes random labels for wildcard DNS, and directly compares nameserver SOA serials, MNAME/RNAME/timers, and NS answers.
- **TLS & HTTPS Security Audit**: Certificate validity, negotiated TLS, HTTPS redirection, HSTS, CSP risk notes, Permissions-Policy, cross-origin isolation headers, cookie security flags, and a bounded `/.well-known/security.txt` presence/format/expiry check. An `OPTIONS` request reports advertised methods only; the scanner does not send write-method probes.
- **Passive Subdomain Inventory**: Queries Certificate Transparency (CT) logs for publicly logged hostnames, resolves discovered names, checks CNAME takeover signatures, labels wildcard-only results, marks risky labels, records available first-seen dates, sorts by risk, and provides CSV export.
- **Optional Common Path Scan**: Checks a bounded set of common web paths and reads same-origin `robots.txt` and sitemap references. It does not crawl directories; discovered paths are labeled for review and are not accessed automatically beyond the bounded checks.
- **Scan Coverage & Change History**: Shows completed, partial, blocked, and optional checks. The browser can compare DNS, CT, TLS certificate, and optional path results with earlier scans stored locally.
- **Scoped Network Inventory & Port Verification**: Nmap-style scoped target resolution and safe port auditing with strict SSRF guardrails (blocking RFC 1918 private subnets `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and loopback `127.0.0.0/8`).
- **BIMI Record Check (RFC 8617)**: Checks the BIMI TXT record and DMARC eligibility. It does not fetch or validate the SVG or VMC.

### 3. Actionable Remediation & Multi-Format Export
- **DNS Fix Generator**: Copy-paste draft records with provider guidance for Cloudflare, AWS Route 53, Namecheap, Hostinger, BigRock, Google Cloud DNS, and Azure DNS. CLI examples are included where supported. Review suggestions before applying them yourself.
- **Re-check after a fix**: Runs a fresh scan, compares findings, and shows the observed record TTL as a cache-delay guide.
- **Finding catalog**: Gives findings stable codes and shared plain-language explanations, attacker context, technical notes, and fixes.
- **Finding code reference**: See [the condition-by-condition code and legacy alias table](docs/FINDING_CODES.md).
- **Export BIND Zone File**: Generates compliant `.zone` configuration files with one click.
- **Standalone Offline Report**: Single-file HTML report with inlined styles that opens without a web server.
- **CLI `dig` Terminal Simulation**: Toggle between visual card view and an interactive colorized terminal output (`dig +noall +answer`).
- **One-Click Markdown & JSON Export**: Instant copyable Markdown summary tables for GitHub/Slack and raw JSON exports for automation.
- **Command-line scanner**: `dns-analyzer example.com` runs the same scan pipeline as the API; supports JSON and minimum-grade gates.
- **Grade badge API**: `/api/badge/{domain}` serves an SVG badge only while a matching in-memory scan result is fresh (60-second cache).

The score covers the seven weighted factors listed above. BIMI findings remain outside the score. Open the score breakdown to see factor points, check completion, finding codes that cost points, excluded factors, and applied caps.

### CLI

The setup script installs the `dns-analyzer` command into `venv/`:

```bash
bash run.sh --setup-only
./venv/bin/dns-analyzer example.com
./venv/bin/dns-analyzer example.com --json
./venv/bin/dns-analyzer example.com --min-grade B
```

| Exit code | Meaning |
|---:|---|
| 0 | Scan succeeded and requested grade requirements passed. |
| 1 | Invalid input or tool failure. |
| 2 | Base grade is below `--min-grade`. |
| 3 | Scan has error-level findings; this takes precedence over grade results. |
| 4 | Grade is provisional and `--require-complete` was set; this takes precedence over code 2. |

`--min-grade` compares the base letter, so `B (incomplete)` satisfies `--min-grade B`; provisional results print a warning. `--require-complete` returns 4 for a provisional grade even without `--min-grade`.

### Current scope and limitations

- DNSSEC trust anchors are stored in `app/data/root_trust_anchors.json`; refresh from IANA with `./venv/bin/python scripts/update_root_trust_anchors.py`, review the source URL, retrieval date, XML SHA-256 and key validity dates, then run `./venv/bin/pytest -q tests/test_dnssec.py`. Do not hand-edit key tags, digests or public keys. The current file records the IANA XML SHA-256 and retrieval date; signatures missing from a response are indeterminate, not bogus.
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
The following excerpt omits unrelated response fields and most factor entries.

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
  "domain_score": { "score": 100, "grade": "A+", "scope": "DNS, email authentication, DNSSEC, takeover evidence, TLS/web, mail transport, and DNS posture", "inconclusive_checks": [], "factors": { "infrastructure": { "score": 20, "max_score": 20, "status": "scored" } } },
  "score_breakdown": { "factors": { "infrastructure": { "points_earned": 20, "maximum": 20, "status": "scored", "checks_completed": 5, "checks_total": 5, "finding_codes_costing_points": [] } }, "caps_applied": [], "applicable_weight": 100, "checks_completed": 20, "checks_total": 20 },
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

### 6. Grade badge
`GET /api/badge/{domain}` returns an SVG badge only while a matching scan is fresh in this server process. Its HTTP cache lifetime is limited to the scan's remaining 60-second TTL; it returns `404` after expiry or when no scan exists.

---

## ⚙️ Deployment & Environment Configuration

The application is configured via environment variables:

| Variable | Default | Purpose / Security Guard |
|:---|:---|:---|
| `ENABLE_ACTIVE_PORT_SCAN` | `false` | Master toggle for active TCP port probes. Requires explicit server policy (`PORT_SCAN_API_KEY` and/or `PORT_SCAN_ALLOWED_DOMAINS`) before probes are permitted. |
| `PORT_SCAN_API_KEY` | *(unset)* | Shared secret token accepted through `Authorization: Bearer <key>`. The JSON `auth_token` field remains temporarily supported for one release and logs a deprecation warning; migrate to the header. |
| `PORT_SCAN_ALLOWED_DOMAINS`| *(unset)* | Comma-separated list of approved target domains/hostnames for active port scans (e.g. `example.com, target.org`). |
| `DNS_ANALYZER_DOCUMENTATION_URL` | `https://example.com/dns-analyzer-scanner` | Documentation link included in the User-Agent sent on outbound HTTP requests. |
| `TRUST_REVERSE_PROXY` | `false` | Inspects `X-Forwarded-For` for client rate limiting. **Security Notice**: Only enable this behind an upstream reverse proxy (e.g. Nginx, Cloudflare) that strips or overwrites untrusted incoming `X-Forwarded-For` headers from external clients to prevent identity spoofing. |
| `TESTING` | `false` | Internal flag used by test harnesses to bypass artificial IP rate limits. |

#### Docker Multi-Stage Testing Note
The [`Dockerfile`](Dockerfile) uses a multi-stage build where the final production runtime stage depends on the test verification stage (`COPY --from=test`). Building the image automatically executes `pytest -v` inside the container. You can also explicitly run the test stage using:
```bash
docker build --target test -t dns-analyzer-test .
```

---

## 📜 RFC Standards Referenced

### Privacy and acceptable use

- The scanner is intended for domains and hosts you own or are authorized to assess. Active TCP port scanning is disabled by default and has a configured server-side authorization/allowlist gate.
- The application configures Python logging to its default stream (normally stderr); it does not configure a log file, external log service, or log-retention period. Host/container logging may capture that stream; its destination and retention are **not configured by the application**. Error detail is written to server logs while API error responses use generic messages.
- Application logs include failed scan domains and exception diagnostics. The configured INFO level can also include `httpx` request logs with outbound URLs. The port-scan deprecation warning records field use but never the token value.
- Scan results are cached in process memory: the main scan cache is 60 seconds (up to 128 domains), common-path results 15 minutes (up to 128 targets), custom DKIM results 15 minutes (up to 128 domain/selector-set entries), and badge SVG data only while the associated scan is fresh (up to 256 badge entries). No database or server-side persistent scan store is configured.
- The in-memory rate limiter stores client IP keys and request timestamps for a rolling 60-second window, with at most 2,048 tracked client entries; exact key lifetime depends on cleanup/eviction. This is process memory, not persistent storage.
- Browser history is stored in that browser profile's local storage: recent domains (up to 5) and up to 60 scan snapshots (up to 5 per domain). It has no application-configured expiry and can be cleared in the dashboard or browser.
- DNS questions are sent to the recursive resolvers configured for the application host. Passive subdomain discovery sends the queried domain to `crt.sh` (`https://crt.sh`). Web/TLS and MTA-STS requests are made to the scanned host or its relevant policy/CNAME hosts. The app does not configure retention policies at those third parties.
- Outbound HTTP requests identify the scanner with a `DNSAnalyzer/2.2.0` User-Agent and the configurable documentation URL above. HTTP requests use pinned public IPs when targeting scanned hosts, bounded timeouts and response sizes, and do not follow redirects automatically.

### Per-scan work limits

The default scan budget is 500 DNS queries and 25 outbound HTTP fetches, shared by modules in a scan. When a budget is exhausted, affected checks are inconclusive. These defaults preserve the limits already used by the primary scan while applying them to optional scan routes as well.

| RFC | Specification | Diagnostic Scope |
|:---|:---|:---|
| **RFC 1034 / 1035** | Domain System Concepts & Facility | Core record structure, CNAME exclusivity, NS delegation |
| **RFC 1912 / 2182** | DNS Operational Guidelines | Authoritative server redundancy, SOA refresh/retry sanity |
| **RFC 5321** | Simple Mail Transfer Protocol (SMTP) | MX existence and mail host address resolution |
| **RFC 7208** | Sender Policy Framework (SPF) | Authorized senders, syntax qualifiers, 10-lookup limit |
| **RFC 7489** | DMARC Domain-based Message Authentication | Reject/quarantine enforcement, alignment, aggregate reports |
| **RFC 6376** | DomainKeys Identified Mail (DKIM) | Selector discovery, public key extraction, cryptographic integrity |
| **RFC 4033 / 4034 / 4035** | DNS Security Extensions (DNSSEC) | DNSKEY inspection and DS-to-DNSKEY delegation matching |
| **RFC 8617** | Brand Indicators for Message Identification (BIMI) | BIMI TXT record presence and DMARC eligibility; no SVG/VMC validation |
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
