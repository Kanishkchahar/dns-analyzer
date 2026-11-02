# DNS Analyzer v2 — Comprehensive Project Guide & Q&A Reference

---

## 1. Executive Summary & Overview

### What is DNS Analyzer?
**DNS Analyzer v2 (InboxShield Edition)** is a modern, high-performance, asynchronous web application designed to perform real-time DNS inspection, rule-based misconfiguration diagnostics, and **email authentication security analysis** on any domain name or web URL.

Instead of running slow, disjointed CLI commands (`dig`, `nslookup`, `host`), DNS Analyzer resolves all critical DNS record types simultaneously (**A, AAAA, MX, NS, TXT, CNAME, SOA**) in a single round-trip using non-blocking asynchronous I/O (`asyncio` + `dnspython`). It then evaluates the resulting DNS zone configuration against an automated diagnostic suite of **9 RFC-standard rule categories**, performs full **SPF / DMARC / DKIM email authentication analysis**, computes an **email health score (A+ to F)**, and outputs a color-coded health dashboard with downloadable offline HTML reports.

---

## 2. Tech Stack & Architectural Justifications

| Layer | Technology Chosen | What It Does | Why It Was Chosen (Rationale) |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | **FastAPI** (Python 3.11+) | REST API endpoints, routing, static hosting, error handling | • Native async/await support for high-concurrency event loops.<br>• Automatic schema validation and OpenAPI documentation.<br>• Ultra-low latency compared to legacy frameworks like Django or Flask. |
| **ASGI Server** | **Uvicorn** | High-performance asynchronous web server | • Lightweight and fast ASGI server based on `uvloop` and `httptools`.<br>• Capable of serving thousands of concurrent requests with minimal memory footprint. |
| **DNS Resolution Engine** | **dnspython** (`dns.asyncresolver`) | Performs live, asynchronous DNS lookups | • The gold standard Python DNS library.<br>• Provides native asynchronous query support, access to raw record sets (`rrset`), TTLs, and explicit exception hierarchies (`NXDOMAIN`, `NoAnswer`, `Timeout`).<br>• Used for primary DNS resolution AND email auth queries (SPF include chains, DMARC TXT at `_dmarc.{domain}`, DKIM selectors at `{selector}._domainkey.{domain}`). |
| **Data Validation & Schemas** | **Pydantic v2** | Request/response data models & domain validation | • Enforces strict RFC domain name regex parsing before network requests are initiated.<br>• Guarantees type-safety and serializes complex data models into clean JSON. |
| **Frontend UI** | **Vanilla HTML5 + CSS3 + Modern JavaScript (ES6+)** | User dashboard, interactive analysis, dynamic DOM rendering | • **Zero dependencies & zero build step** (no Webpack, Vite, React, or heavy node_modules).<br>• Instant load times and zero supply-chain/npm vulnerabilities.<br>• Accessible UI with Geist typography, ARIA live status updates, and dark theme design. |
| **Report Generation Engine** | **Jinja2** | Generates standalone offline HTML diagnostic reports | • Fast, secure server-side HTML templating.<br>• Inlines all CSS styling and data tables into a single portable `.html` file that security teams can view offline or email. |

---

## 3. System Architecture & End-to-End Workflow

```
               +-------------------------------------------+
               | User Browser (Frontend UI)               |
               | - Enter domain or full URL                |
               +--------------------+----------------------+
                                    |
                          POST /api/analyze
                                    |
                                    v
               +-------------------------------------------+
               | FastAPI Backend (app/main.py)             |
               | - Pydantic domain regex validation        |
               +----+---------------+----------------+-----+
                    |               |                |
                    v               v                v
          +--------------+  +-----------+  +------------------+
          | DNS Resolver  |  |   SPF     |  | DMARC + DKIM     |
          | 7 queries     |  |  Parser   |  |  Concurrent      |
          | concurrent    |  |  Counter  |  |  Selector Scan   |
          | (resolver.py) |  |  Flatten  |  | (email_auth.py)  |
          +-------+------+  | (spf.py)  |  +--------+---------+
                  |          +-----+-----+           |
                  |                |                  |
                  +--------+------+------+-----------+
                           |
                           v
               +-------------------------------------------+
               | Rule Analyzer Engine                      |
               | - 9 DNS checks (analyzer.py)              |
               | - SPF analysis (spf.py)                   |
               | - DMARC/DKIM analysis (email_auth.py)     |
               | - Email Health Score (0-100, A+ to F)     |
               +--------------------+----------------------+
                                    |
                                    v
               +-------------------------------------------+
               | JSON Response / Report Generator          |
               | - JSON -> Frontend DOM Render             |
               | - GET /api/report/{domain} -> Jinja2 HTML |
               +-------------------------------------------+
```

### Execution Flow Details:
1. **Input Sanitization**: User inputs `https://example.com/some/path?param=1` or `example.com`. The frontend extracts the clean hostname (`example.com`).
2. **Schema & Regex Validation**: FastAPI receives the JSON payload. Pydantic validates the domain against `DOMAIN_RE = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"`.
3. **Concurrent Async Lookups**: `app.resolver.resolve_domain()` spins up 7 asynchronous query tasks in `asyncio.gather`. Rather than waiting sequentially (e.g., 7 × 150ms = ~1.05s), all primary records return in parallel (~150ms total).
4. **Secondary Host Resolution**: Authoritative Nameservers (`NS`) and Mail Servers (`MX`) are extracted and queried for their `A` records to ensure they actually resolve.
5. **Email Authentication Analysis** (v2):
   - **SPF**: Parse TXT records for `v=spf1`, recursively count DNS lookups against the RFC 7208 limit of 10, flatten include chains to IP ranges.
   - **DMARC**: Query `_dmarc.{domain}` TXT, parse policy/enforcement/reporting tags.
   - **DKIM**: Concurrently scan 15 common selectors (`google`, `default`, `selector1`, `selector2`, `s1`, `s2`, `dkim`, `mail`, `k1`, `mandrill`, `zendesk`, `amazonses`, etc.) and validate public keys.
   - **Email Health Score**: Compute a 0-100 score (A+ to F) from combined SPF/DMARC/DKIM findings.
6. **Rule-Based RFC Analysis**: `app.analyzer.analyze()` runs 9 pure diagnostic functions against the structured record dictionary. Email auth findings are merged into the findings list.
7. **Result Presentation**: JSON is returned to the client for live dashboard rendering (including animated score ring, auth cards), and the user can download a standalone self-contained HTML report.

---

## 4. Diagnostic Rules & Security Checks Explained

### A. Core DNS Infrastructure Rules (9 Categories)

| # | Check Function | What It Verifies | Severity | RFC / Standard Reference | Why It Matters |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `check_domain_resolves` | Domain has at least one valid `A` (IPv4) or `AAAA` (IPv6) record | **ERROR** | RFC 1035 | If a domain does not resolve to an IP, it is completely unreachable by web browsers and clients. |
| **2** | `check_ns_exists` | Authoritative Nameserver (`NS`) records exist | **ERROR** | RFC 1034 / 1035 | Without NS records, DNS resolvers cannot locate the authoritative source of truth for the zone. |
| **3** | `check_ns_redundancy` | Domain has 2 or more nameservers | **WARNING** | RFC 1035 (Section 2.2) | Having only 1 NS creates a single point of failure (SPOF). If that server goes down, the entire domain goes offline. |
| **4** | `check_ns_resolves` | Each NS hostname resolves to an IP (`A` record) | **ERROR** | RFC 1035 | If an NS record points to an unresolvable hostname, DNS resolution will intermittently fail or hang. |
| **5** | `check_mx_exists` | MX records exist for the domain | **INFO** | RFC 5321 | Informs the user whether the domain is configured to receive email. Informational only, as many subdomains don't handle email. |
| **6** | `check_mx_resolves` | Each mail exchange host resolves to an `A` record | **ERROR** | RFC 5321 | If an MX host does not resolve to an IP, incoming emails sent to this domain will bounce or be permanently dropped. |
| **7** | `check_cname_conflict` | `CNAME` does not coexist with other record types (`A`, `AAAA`, `MX`, `NS`, `TXT`) | **ERROR** | RFC 1034 (Section 3.6.2) / RFC 2181 | A CNAME represents an alias for the entire node. Coexisting with other types violates DNS specs and causes undefined resolution behavior. |
| **8** | `check_soa_sanity` | SOA parameters: `refresh >= retry`, and `expire >= 172,800s` (2 days) | **WARNING** | RFC 1912 / RFC 2182 | If `refresh < retry`, secondary DNS servers behave abnormally. If `expire` is too low, secondary nameservers stop serving the zone prematurely during master downtime. |
| **9** | `check_ttl_sanity` | TTL is not `0` and not excessive (`> 604,800s` / 7 days) | **WARNING / INFO** | RFC 1035 / Best Practices | `TTL = 0` disables caching, spiking server latency and query costs. `TTL > 7 days` means emergency IP migrations will take over a week to propagate globally. |

### B. Email Authentication Suite (InboxShield v2)

| Protocol | Check | Severity | RFC Reference | Explanation |
| :--- | :--- | :--- | :--- | :--- |
| **SPF** | Existence | **ERROR** | RFC 7208 | Missing SPF allows any host to send fraudulent emails claiming to be from this domain. |
| **SPF** | Multiple Records | **ERROR** | RFC 7208 §3.2 | Having >1 SPF record causes receivers to return `PermError` and drop mail. |
| **SPF** | 10-Lookup Limit | **ERROR / WARN** | RFC 7208 §4.6.4 | Lookups > 10 trigger `PermError`. Lookups 8–10 are flagged as warning. Includes recursive chain tree and auto-flattening. |
| **SPF** | Policy (`all`) | **ERROR / WARN / INFO** | RFC 7208 §4.6.2 | `+all` allows anyone (critical flaw). `?all` is neutral (weak). `~all` is softfail. `-all` is strict enforcement. |
| **SPF** | Deprecated `ptr` | **WARNING** | RFC 7208 §5.5 | `ptr` mechanism is formally deprecated due to severe load and unreliability. |
| **DMARC** | Existence | **ERROR** | RFC 7489 | Without DMARC at `_dmarc.{domain}`, spoofed emails bypass domain policy. |
| **DMARC** | Policy (`p=`) | **WARN / INFO** | RFC 7489 | `p=none` is audit-only. `p=quarantine` moves to spam. `p=reject` drops unauthenticated mail. |
| **DMARC** | Reporting (`rua=`) | **WARNING** | RFC 7489 | Without aggregate reporting, the domain owner cannot monitor spoofing attacks. |
| **DMARC** | Enforcement (`pct=`) | **WARNING** | RFC 7489 | `pct < 100` leaves a fraction of emails vulnerable to spoofing. |
| **DKIM** | Common Selectors | **WARN / INFO** | RFC 6376 | Scans 15 major selectors (`google`, `selector1`, `default`, etc.). Checks public key presence and flags test mode (`t=y`). |
| **Score** | Email Health Grade | **A+ to F** | Composite Metric | Starts at 100, deducts -15 per error and -8 per warning. Maps to animated visual badge. |

---

## 5. Comprehensive Presentation & Interview Q&A

### Category A: Core Concept & Problem Domain

#### Q1: What problem does DNS Analyzer solve?
> **Answer:** DNS is the foundational backbone of the internet, but misconfigured DNS records often lead to website downtime, dropped emails, and security vulnerabilities. Traditional tools like `dig` or `nslookup` are command-line utilities that only query one record type at a time and require manual human interpretation. DNS Analyzer automates the entire process: it queries all 7 major record types concurrently, runs 9 RFC-based compliance checks, and displays color-coded diagnostics and exportable reports in seconds.

#### Q2: What are the main DNS record types analyzed by this application?
> **Answer:**
> 1. **A**: Maps domain to IPv4 address (e.g., `93.184.216.34`).
> 2. **AAAA**: Maps domain to IPv6 address (e.g., `2606:2800:220:1:248:1893:25c8:1946`).
> 3. **MX**: Mail Exchange servers and their priority rankings.
> 4. **NS**: Authoritative Name Servers responsible for the domain zone.
> 5. **TXT**: Text records often used for domain verification, SPF, DKIM, and DMARC.
> 6. **CNAME**: Canonical Name aliases pointing one name to another.
> 7. **SOA**: Start of Authority containing zone administrative metadata (serial, refresh, retry, expire, minimum TTL).

#### Q3: Why is DNS misconfiguration dangerous for an organization?
> **Answer:**
> - **Availability Loss:** A single nameserver failure with no redundancy takes the domain offline.
> - **Email Outages:** An unresolvable MX host results in dropped or bounced client communications.
> - **Security Risks:** Dangling CNAMEs can lead to subdomain takeover attacks.
> - **Latency & Performance:** Misconfigured TTLs (e.g., TTL=0) overload DNS servers and add round-trip latency to every user request.

---

### Category B: Technical Implementation & Architecture

#### Q4: Why did you use `asyncio.gather` instead of sequential queries?
> **Answer:** If we query 7 record types sequentially and each query takes ~150ms, the total scan time would be over 1 second (1050ms), worsening under high network jitter. By using `asyncio.gather`, all 7 queries run concurrently across the event loop, completing in the time of the single slowest query (~150ms total), giving a **7x speedup**.

#### Q5: How does the application handle domains that do not have certain records (e.g., No MX or No AAAA)?
> **Answer:** In `app/resolver.py`, the `_safe_query` helper catches dnspython exceptions (`NXDOMAIN`, `NoAnswer`, `NoNameservers`, and `Timeout`). Instead of crashing or throwing an unhandled 500 error, it returns a structured dictionary: `{"status": "not_found", "records": [], "ttl": 0}`. The analyzer then interprets whether the absence of that record is an Error, Warning, or Informational notice.

#### Q6: Why is CNAME coexisting with other records flagged as an ERROR?
> **Answer:** Under **RFC 1034 (Section 3.6.2)** and **RFC 2181**, if a CNAME record exists at a node, no other data (like A, MX, TXT) may exist at that same node. If a CNAME coexists with an A record, resolvers may follow the alias or return the A record unpredictably, breaking mail routing, web hosting, and DNSSEC.

#### Q7: Why did you choose Vanilla JS instead of a framework like React, Vue, or Angular?
> **Answer:**
> 1. **Zero build overhead:** No `npm install`, Webpack, Babel, or node_modules dependencies.
> 2. **Performance:** The page loads in milliseconds with virtually zero initial bundle footprint.
> 3. **Simplicity:** The project has straightforward DOM update requirements (form submission, spinner toggle, table population). Vanilla JS with modern ES6 `fetch` and template strings provides clean, maintainable, and high-performance code.

#### Q8: How does the offline HTML report download work?
> **Answer:** When a user accesses `/api/report/{domain}`, FastAPI re-executes the resolution and analysis pipeline. It passes the resulting data to Jinja2, which renders a self-contained HTML template with fully embedded CSS styling. FastAPI returns this response with the HTTP header `Content-Disposition: attachment; filename="dns-report-{domain}.html"`, prompting the browser to download the file directly. The resulting file works completely offline without needing any external CDN or server connection.

---

### Category C: SOA & TTL Deep Dive

#### Q9: What are SOA Refresh, Retry, and Expire values, and why do we check them?
> **Answer:**
> - **Refresh:** How often secondary (slave) nameservers poll the primary (master) server for zone updates.
> - **Retry:** How soon secondary nameservers retry if the primary server fails to respond during a refresh attempt.
> - **Expire:** The maximum time secondary nameservers continue answering queries if the primary server remains unreachable.
> - **Why we check:** If `Refresh < Retry`, it violates logical hierarchy (you should not wait longer to retry than to routinely refresh). If `Expire < 2 days` (172,800s), secondary servers might stop serving the zone prematurely during a standard weekend server maintenance window.

#### Q10: What are the trade-offs of low vs high DNS TTL (Time-to-Live)?
> **Answer:**
> - **Low TTL (e.g., 0 to 60 seconds):**
>   - *Advantage:* Fast propagation of IP/host changes during migrations or disaster recovery.
>   - *Disadvantage:* Disables or degrades caching, causing increased DNS query traffic, higher server load, and added latency for client connections.
> - **High TTL (e.g., > 7 days):**
>   - *Advantage:* Maximizes DNS cache hits and minimizes lookups.
>   - *Disadvantage:* If an IP changes or an incident occurs, outdated records remain cached globally across ISPs for days, causing extended downtime.

---

### Category D: Testing, Security & Future Scope

#### Q11: How is the rule analyzer tested without making live internet requests?
> **Answer:** The analyzer in `app/analyzer.py` is written as **pure, decoupled functions** that take a plain Python dictionary (`resolver_data`) and return a list of `Finding` models. This allows 100% unit test coverage using mock dictionaries (e.g., passing a dictionary with only 1 NS record to verify `check_ns_redundancy` triggers a warning) without any network I/O or external dependencies.

#### Q12: What enhancements were delivered in v2, and what is planned for v3?
> **Answer:**
> **Delivered in v2 (InboxShield Edition):**
> 1. Full SPF RFC 7208 compliance scanner with recursive lookup counting, warning at 8-10, error at >10, and automatic record flattening.
> 2. DMARC policy evaluator (parsing `p=`, `pct=`, `rua=`, `adkim`, `aspf`).
> 3. Concurrent DKIM selector discovery across 15 popular providers with public key validation.
> 4. Interactive Email Health Score ring with dynamic grading (A+ to F).
> 5. Updated offline report generation incorporating all email authentication cards.
>
> **Future Scope for v3:**
> 1. **DNSSEC Verification:** Cryptographic chain-of-trust inspection (DS, DNSKEY, RRSIG validation).
> 2. **Subdomain Takeover Scanner:** Checking dangling CNAMEs against known cloud provider signatures (e.g., unclaimed AWS S3 buckets, GitHub Pages).
> 3. **Database & Scan History:** Storing historical scans in PostgreSQL to detect DNS drift and zone modifications over time.
> 4. **Automated Alerting:** Webhook integrations for Slack/Discord/Email when DNS health degradations are detected.

---

### Category E: Email Security & InboxShield Deep Dive

#### Q13: What is SPF Record Flattening and why is it valuable?
> **Answer:** RFC 7208 strictly limits SPF evaluation to 10 DNS lookups. Large enterprises using multiple SaaS services (Google Workspace, Zendesk, Salesforce, SendGrid) easily exceed this limit, leading to legitimate emails failing SPF checks (`PermError`). SPF Flattening recursively crawls all `include:` and `redirect=` directives, resolves their underlying `A` and `MX` records to IPv4 (`ip4:`) and IPv6 (`ip6:`) CIDR ranges, and generates a single flat SPF record that requires **0 DNS lookups**. Our tool generates this suggestion automatically.

#### Q14: How does DMARC policy hierarchy work?
> **Answer:** DMARC operates on three policy levels defined in `p=`:
> - `p=none`: Monitoring mode. Emails that fail SPF/DKIM are still delivered to inboxes, but daily aggregate reports (`rua`) are generated.
> - `p=quarantine`: Intermediate enforcement. Failing emails are redirected to spam/junk folders.
> - `p=reject`: Maximum enforcement. Unauthorized emails claiming to be from your domain are outright rejected by recipient mail servers at the SMTP stage.

#### Q15: Why can't DKIM be queried with a single wildcard or generic DNS lookup?
> **Answer:** DKIM records are published at `{selector}._domainkey.{domain}`. The DNS protocol does not allow clients to "list" all subdomains under `_domainkey` without zone transfers (AXFR), which are disabled on secure nameservers. Therefore, our scanner uses `asyncio.gather` to concurrently query 15 of the most widely adopted selector names (`google`, `default`, `s1`, `k1`, `mandrill`, `amazonses`, etc.) in parallel. If a domain uses a custom, non-standard selector, we transparently notify the user.

---

## 6. How to Run the Project

```bash
# 1. Clone or navigate to the repository
cd /home/kanishk/Desktop/dns-analyzer

# 2. Setup virtual environment & dependencies
bash setup.sh

# 3. Start the server (default port: 8000)
bash start.sh

# 4. Open in browser
# Visit http://127.0.0.1:8000
```
