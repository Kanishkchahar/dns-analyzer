# 🛡️ DNS Analyzer 2.2.0 — Security Posture Cockpit
## Master Presentation, Demo Script & Technical Viva Reference

> **Project Author:** Kanishk  
> **Version:** 2.2.0 — Security Posture Cockpit Edition
> **Tech Stack:** Python 3.11+ · FastAPI · dnspython · Vanilla JS · Jinja2 · Uvicorn · Pytest

---

## 📑 Table of Contents
1. [Elevator Pitch & Opening Statement](#1-elevator-pitch--opening-statement)
2. [Live Demonstration Script (2–3 Minutes)](#2-live-demonstration-script-23-minutes)
3. [The Security Posture Cockpit (Asymmetric Bento Grid)](#3-the-security-posture-cockpit-asymmetric-bento-grid)
4. [Executive Summary & Problem Statement](#4-executive-summary--problem-statement)
5. [System Architecture & Concurrency Workflow](#5-system-architecture--concurrency-workflow)
6. [Comprehensive Scan Directory: What Scans It Runs, What They Tell You & Why They Are Critical](#6-comprehensive-scan-directory-what-scans-it-runs-what-they-tell-you--why-they-are-critical)
7. [RFC Rules & Security Standards Reference](#7-rfc-rules--security-standards-reference)
8. [Comprehensive Interview & Viva Q&A (Categories A–F)](#8-comprehensive-interview--viva-qa)
9. [Pro Tips to Impress Teachers & Evaluators](#9-pro-tips-to-impress-teachers--evaluators)
10. [Closing Statement](#10-closing-statement)
11. [Quick Start & Scripts](#11-quick-start--scripts)

---

## 1. Elevator Pitch & Opening Statement

> *"Good morning / afternoon. Today, I am presenting **DNS Analyzer 2.2.0 — Security Posture Cockpit Edition**.*
>  
> *DNS is the foundational routing fabric of the modern internet, and email authentication is our frontline defense against identity spoofing and credential theft. Yet, misconfigured DNS zones silently bring down mission-critical platforms, cause transactional emails to be marked as spam, and expose companies to catastrophic subdomain hijacking.*  
>  
> *Traditional command-line utilities like `dig` or `nslookup` expose low-level answers that take experience to interpret. DNS Analyzer brings DNS, email, TLS, and selected web-surface checks into one dashboard. It reports scan coverage and inconclusive results, and provides focused exports and remediation guidance. Scan time depends on DNS and remote service response times."*

---

## 2. Live Demonstration Script (2–3 Minutes)

Run the unified runner:
```bash
bash run.sh
# Open http://127.0.0.1:8000
```

### Recommended Test Domains (Demo in this exact sequence):

| # | Domain to Test | What It Proves to the Audience |
|---|----------------|---------------------------------|
| **1** | `cloudflare.com` (or click Quick Chip) | **Posture Overview:** Inspect the live score and available DNS, mail, TLS, DNSSEC delegation, and nameserver checks. Results depend on current DNS and service responses; do not assume a fixed grade. |
| **2** | `google.com` | **Email Scale:** Strict DMARC enforcement, strong SPF, multiple verified DKIM selector keys, and redundant authoritative nameservers. |
| **3** | `https://www.boot.dev/dashboard` | **Automatic URL Sanitization:** Paste a full dirty URL with protocol, path, and query parameters. The platform instantly extracts `boot.dev` automatically with zero user effort. |
| **4** | `example.com` | **Remediation Drafts:** Reveals missing SPF/DMARC records and copy-paste draft suggestions with provider guidance. Suggestions are not applied automatically. |
| **5** | `invalid!!!domain` | **Resilience & Validation:** Pydantic validation rejects malformed input with a clean HTTP 400 error banner — no server exceptions or unhandled tracebacks. |

### Key Features to Highlight During the Demo:
1. ⚡ **Asynchronous Concurrency**: *"Independent DNS and security checks run concurrently with bounded timeouts. Results can vary with DNS, CT, and target response times."*
2. 🍱 **Bento Grid Dashboard**: *"The score uses seven weighted factors. Open the score breakdown for points, incomplete checks, excluded factors, and caps."*
3. 🛡️ **Takeover Fingerprint Checks**: *"Checks known CNAME service patterns. DNS-only evidence is a candidate unless an entry is explicitly verified and opts into NXDOMAIN confirmation. Page matches on the currently unverified catalog are candidates, not confirmed findings."*
4. 🔐 **DNSSEC Inspection**: *"By default, compares observed DNSKEY and DS records only. The opt-in chain validator reports separate evidence and does not affect the score."*
5. 📈 **SPF 10-Lookup Recursion Meter & Flattener**: *"Visual bar tracking lookups against the strict RFC 7208 limit of 10, with an automatic CIDR flattener that optimizes over-limit records to 0 lookups."*
6. ✨ **BIMI Brand Inbox Validation**: *"Audits whether the domain publishes a verified SVG logo and satisfies strict DMARC criteria for official avatar display in Gmail and Apple Mail."*
7. 🔧 **Copy-Paste Fix Drafts & BIND Export**: *"Generates draft record values, provider-specific guidance, and a BIND snippet. You review and apply suggested changes yourself."*
8. ⌨️ **Radical Keyboard Ergonomics**: *"Operate the entire dashboard without a mouse: `/` focuses search, `?` opens help, `1`–`4` test samples, `f` filters findings, `v` toggles CLI dig view, `c` copies shareable links, `m` copies Markdown summaries, `j` exports JSON, `d` downloads offline reports, and `z` exports BIND zone files."*
9. 🧭 **Scan Coverage & Change History**: *"See which checks completed, were partial, were blocked, or are optional. Compare DNS, CT inventory, TLS certificate, and optional path results with earlier scans saved in this browser."*
10. 🌐 **Bounded Web Path Review**: *"Run a separate fixed-path check that can read same-origin robots.txt and sitemap references. It is bounded and does not recursively crawl directories."*

---

## 3. The Security Posture Cockpit (Asymmetric Bento Grid)

The dashboard overview is structured as a **Two-Tier Security Posture Cockpit** inspired by industry benchmarks (Vercel Geist, Linear, and Cloudflare Radar):

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  🌐 cloudflare.com  ·  Scanned Nov 7, 2026 12:00 UTC        [ Share Link ] [ Copy MD ] [ Export JSON ]│
├─────────────────────────────────────┬──────────────────────────────────┬───────────────────────────────┤
│                                     │ 🌐 DNS INFRASTRUCTURE            │ ✉️ EMAIL AUTHENTICATION       │
│       DNS & EMAIL POSTURE SCORE     │                                  │                               │
│                                     │  A/AAAA Records Resolved         │  Email Authentication          │
│         ╭───────────────╮           │  • IPv4: 2 Addresses Resolved    │  • SPF: Valid (-all policy)   │
│        ╱                 ╲          │  • IPv6: 2 Addresses Resolved    │  • DMARC: Strict (p=reject)   │
│       │     Grade A+      │         │  • NS: 5 Redundant Servers       │  • DKIM: Verified Selectors   │
│       │     100 / 100     │         │                                  │                               │
│        ╲                 ╱          │  [ Status: Healthy ● ]           │  [ Status: Enforced ● ]       │
│         ╰───────────────╯           │  [ DNS Records → ]               │  [ Email Auth → ]             │
│                                     ├──────────────────────────────────┼───────────────────────────────┤
│   DNS and email posture overview    │ 🔐 CRYPTOGRAPHY & TAKEOVER       │ 🔧 REMEDIATION DRAFTS         │
│                                     │                                  │                               │
│   ┌────────┐ ┌────────┐ ┌────────┐  │  Partial DNSSEC inspection       │  Copy-paste suggestions      │
│   │ errors │ │ warnings│ │  info  │  │  • DS/DNSKEY match (if observed)  │  • Review before publishing  │
│   └────────┘ └────────┘ └────────┘  │  • Takeover candidates listed     │                               │
│                                     │  [ Review findings ]             │  [ Remediation drafts ]      │
│  [ Filter findings ]                │  [ Threat Defense → ]            │  [ BIND export ]              │
└─────────────────────────────────────┴──────────────────────────────────┴───────────────────────────────┘
```

*The wireframe above is illustrative. Scores, counts, and statuses depend on the domain scanned and are not a promised result. The score weights infrastructure 20, email authentication 25, DNSSEC 20, takeover evidence 15, TLS/web 10, mail transport 5, and DNS posture 5. Not-applicable factors and factors with no completed checks are excluded; remaining weights are normalized to 100.*
*In a partially observed factor, each inconclusive check receives neutral 50% credit; the score breakdown lists each check and the scoring policy. The score label shows `based on X of Y factors`. If excluded factor weight exceeds 30%, the grade is provisional and shown as `(incomplete)`. For the 15-point takeover factor, safe earns 15, candidate earns 6.75 (`15 × 0.45`) and deducts 8.25 (`15 × (1 − 0.45)`), confirmed earns 0 and triggers the cap of 39; inconclusive and not-applicable are excluded and never trigger a cap. AXFR caps at 54 and bogus DNSSEC at 39.*

### Design Notes:
1. **Dominant Visual Centerpiece**: The animated SVG health ring sits on the left, anchoring the dashboard. Executives and non-technical stakeholders instantly comprehend domain health in 3 seconds.
2. **Zero Text Truncation**: Squeezing 4 metrics into a single row forces ellipsis truncation (`IPv4 (2...`, `Cryptograph...`). The 2×2 layout gives each quadrant ample breathing room for complete sentences, bullet points, and live status dots.
3. **Seamless Progressive Disclosure**: High-level status is presented in the Bento overview, while deep protocol details (RFC parameters, hex public keys, raw records) reside in dedicated segmented tabs accessible with one click.

---

## 4. Executive Summary & Problem Statement

### The Problem:
* **72% of organizations** suffer DNS outages, with an average downtime cost exceeding $900,000 per incident (EfficientIP Global DNS Threat Report).
* **91% of targeted cyberattacks** initiate via spear-phishing or domain spoofing (FBI Internet Crime Report).
* **Stale CNAMEs** can point to third-party resources that may be claimable. This project uses provider fingerprints; it does not provide CVE-based threat hunting or prove provider-side claimability.
* Traditional utilities (`dig`, `nslookup`) are single-query, CLI-only, and provide no contextual policy analysis or remediation.

### The Solution:
DNS Analyzer 2.2.0 combines DNS and email configuration checks, partial DNSSEC delegation inspection, selected web checks, and known-pattern takeover detection in a browser dashboard. The backend uses Python dependencies; the browser interface is served as static HTML, CSS, and JavaScript without a frontend build step.

---

## 5. System Architecture & Concurrency Workflow

```
               ┌─────────────────────────────────────────────────────────┐
               │           Browser UI (Vanilla JS & Modern CSS)          │
               │  Bento Grid Cockpit · Live Telemetry · Keyboard Nav (/) │
               └────────────────────────────┬────────────────────────────┘
                                            │ POST /api/analyze {"domain": "..."}
                                            ▼
               ┌─────────────────────────────────────────────────────────┐
               │              FastAPI Gateway (app/main.py)              │
               │         Strict Pydantic URL & Domain Validation         │
               └────┬──────────────┬──────────────┬──────────────┬───────┘
                    │              │              │              │
                    ▼              ▼              ▼              ▼
          ┌────────────────┐ ┌──────────┐ ┌─────────────┐ ┌──────────────┐
          │ Async Resolver │ │ SPF Deep │ │ DMARC/DKIM  │ │ Cryptography │
          │ 7 Record Types │ │ Engine   │ │ Scanner     │ │ & Takeovers  │
          │ A, AAAA, MX,   │ │ Parse,   │ │ Policy,     │ │ DNSSEC, DS,  │
          │ NS, TXT, CNAME,│ │ Flatten, │ │ 15 Selectors│ │ Dangling     │
          │ SOA            │ │ 10-Limit │ │ rua/ruf     │ │ CNAMEs, BIMI │
          │ (resolver.py)  │ │ (spf.py) │ │(email_auth) │ │ (takeover/..)│
          └────────┬───────┘ └────┬─────┘ └──────┬──────┘ └──────┬───────┘
                   └──────────────┼──────────────┼───────────────┘
                                  ▼
               ┌─────────────────────────────────────────────────────────┐
               │           Comprehensive RFC Rule Analysis Engine        │
               │ • 10 DNS Infrastructure Checks (analyzer.py)            │
               │ • SPF Recursion Tree & Flattening (spf.py)              │
               │ • DMARC Policy & Weighted Score Calculation (0-100)     │
               │ • Partial DNSSEC Check & Takeover Fingerprints          │
               │ • Copy-Paste Drafts & BIND Zone Export (remediation)    │
               └────────────────────────────┬────────────────────────────┘
                                            │
                            ┌───────────────┴───────────────┐
                            ▼                               ▼
              ┌───────────────────────────┐   ┌───────────────────────────┐
              │ Dynamic Dashboard Stream  │   │ Standalone Offline Report │
              │ Bento Cockpit + dig CLI   │   │ Jinja2 Embedded HTML File │
              └───────────────────────────┘   └───────────────────────────┘
```

---

## 6. Comprehensive Scan Directory: What Scans It Runs, What They Tell You & Why They Are Critical

The main analysis runs the checks below. Common web path checks and active port probes are separate, optional actions; coverage labels identify checks that were not run or could not complete.

---

### Category 1: Core DNS Infrastructure Scans

#### 1. IPv4 Resolution Scan (`A` Records)
* **What It Does**: Queries the apex domain for 32-bit IPv4 address records (`A`).
* **What It Tells You**: Returns the IPv4 addresses where the domain's web servers or proxy edge nodes reside.
* **Why It Is Important**: Fundamental to web connectivity. If an `A` record is absent and no `AAAA` or `CNAME` exists, the domain is completely dark and unresolvable for 90%+ of internet users.

#### 2. IPv6 Record Presence (`AAAA` Records)
* **What It Does**: Queries the domain for 128-bit IPv6 address records (`AAAA`).
* **What It Tells You**: Confirms whether the domain supports native IPv6 routing or is legacy IPv4-only.
* **Why It Is Important**: Over 45% of global Google users now access services via IPv6. On mobile networks (5G) and emerging ISP infrastructure that operate IPv6-only, lack of `AAAA` records causes traffic to route through translation gateways (NAT64/DNS64), adding latency and potential connection drops.

#### 3. Authoritative Nameserver Existence Scan (`NS` Records)
* **What It Does**: Checks whether authoritative nameserver records (`NS`) are published for the zone (RFC 1034 / 1035).
* **What It Tells You**: Identifies the primary authoritative servers responsible for answering all DNS queries for the domain.
* **Why It Is Important**: Without authoritative `NS` records, recursive DNS resolvers across the globe cannot locate the zone's records, resulting in total domain failure (`SERVFAIL`).

#### 4. Nameserver Redundancy & Fault Tolerance Scan (RFC 1035 §2.2)
* **What It Does**: Counts the number of distinct authoritative nameservers and validates redundancy (minimum of 2 required).
* **What It Tells You**: Confirms whether the domain has distributed DNS resilience or a Single Point of Failure (SPOF).
* **Why It Is Important**: A single nameserver leaves the zone without a second configured authority if that server becomes unavailable. Operational guidance recommends multiple nameservers; this scanner counts NS hostnames and does not prove their network or provider independence.

#### 5. Nameserver Host Address Resolution Check
* **What It Does**: Resolves each authoritative nameserver hostname to an underlying IP address.
* **What It Tells You**: Verifies that nameserver hostnames are active and can be reached by recursive resolvers.
* **Why It Is Important**: A registered nameserver hostname that fails to resolve is a "lame delegation". Resolvers attempting to query a dead nameserver suffer 3–5 second timeouts before failing over, causing painful page-load latency or random resolution failures.

#### 6. Mail Exchange Existence & Host Resolution Scan (`MX` Records — RFC 5321)
* **What It Does**: Fetches MX records, parses priority rankings, and resolves each mail server hostname to an active IP.
* **What It Tells You**: Confirms the incoming mail infrastructure, failover order, and server availability.
* **Why It Is Important**: If a company sends or receives email, its MX records must resolve. If an MX points to an unresolvable hostname, external mail servers (Gmail, Microsoft 365) immediately bounce incoming messages with `550 Host not found` errors.

#### 7. CNAME Conflict & Node Exclusivity Scan (RFC 1034 §3.6.2 & RFC 2181)
* **What It Does**: Audits whether a Canonical Name (`CNAME`) record coexists with other record types (`A`, `MX`, `NS`, `SOA`, `TXT`) at the same domain node.
* **What It Tells You**: Detects invalid alias configurations that break DNS protocol rules.
* **Why It Is Important**: RFC 1034 dictates that if a node has a CNAME, it can have *no other record types*. If a CNAME is placed on an apex domain (`example.com`), recursive resolvers ignore the domain's `MX` and `NS` records, silently dropping emails and causing unpredictable routing glitches.

#### 8. Start of Authority (SOA) Parameter Sanity Scan (RFC 1912 / 2182)
* **What It Does**: Inspects the zone's primary master (`mname`), administrator email (`rname`), serial number, refresh, retry, expire, and minimum TTL intervals.
* **What It Tells You**: Verifies the operational synchronization health between primary and secondary nameservers.
* **Why It Is Important**: 
  - If `refresh < retry`, secondary servers poll out of order.
  - If `expire` is under 172,800 seconds (2 days), a temporary outage on the primary server causes secondary servers to discard all zone records, wiping the domain from the internet.

#### 9. Time-to-Live (TTL) Extreme Range & Caching Sanity Scan (RFC 1035)
* **What It Does**: Audits TTL values across all returned DNS records for extreme anomalies.
* **What It Tells You**: Flags `TTL = 0` (no caching) or excessively high TTL (`TTL > 7 days`).
* **Why It Is Important**:
  - `TTL = 0`: Disables caching completely. Every single user request hammers the authoritative nameserver, causing severe server load and slow page-load times.
  - `TTL > 7 days`: Changes to IP addresses or server migrations take up to a week to propagate, paralyzing emergency failover responses during incidents or outages.

#### 10. Certificate Authority Authorization (CAA) Policy Check
* **What It Does**: Queries CAA records and checks parent labels when the submitted hostname has no direct CAA answer.
* **What It Tells You**: Shows whether certificate issuance is restricted to listed certificate authorities and identifies inherited policy.
* **Why It Is Important**: CAA gives domain owners a DNS mechanism to express which certificate authorities may issue certificates for their names. Interpret wildcard (`issuewild`) and ordinary issuance policy separately when reviewing the records.

---

### Category 2: Email Authentication & Anti-Spoofing Scans (InboxShield)

#### 11. SPF (Sender Policy Framework) Record & Policy Scan (RFC 7208)
* **What It Does**: Parses `v=spf1` TXT records, evaluates mechanisms (`ip4`, `ip6`, `include`, `a`, `mx`), and evaluates the trailing policy (`-all`, `~all`, `?all`, `+all`).
* **What It Tells You**: Identifies the exact IP addresses and cloud providers legally authorized to send email for this domain.
* **Why It Is Important**: 
  - Missing SPF allows any attacker anywhere in the world to forge emails using your domain.
  - `+all` explicitly authorizes the entire internet to spoof your domain.
  - `-all` (HardFail) informs recipient servers to outright reject unauthorized senders.

#### 12. Multiple SPF Record Conflict Scan (RFC 7208 §3.2)
* **What It Does**: Detects whether more than one `v=spf1` TXT record exists in the zone.
* **What It Tells You**: Detects duplicate SPF records created when different teams or IT admins publish separate records for Google, Salesforce, or Zendesk.
* **Why It Is Important**: RFC 7208 §3.2 mandates that a domain MUST NOT publish multiple SPF records. When receiving mail servers encounter multiple SPF records, they immediately return `PermError`, causing legitimate marketing, transactional, and executive emails to be marked as spam or dropped.

#### 13. SPF Recursive 10-Lookup Limit & Tree Traversal Scan (RFC 7208 §4.6.4)
* **What It Does**: Recursively traverses and counts DNS lookups triggered by `include:`, `a`, `mx`, `ptr`, and `redirect` mechanisms, subject to recursion and scan time limits.
* **What It Tells You**: The exact number of DNS lookups required to evaluate the SPF record, warning if approaching the limit (8–10) or in violation (>10).
* **Why It Is Important**: RFC 7208 limits lookups to 10 to prevent infinite recursive DNS amplification attacks. When a company uses Google Workspace (1 lookup) + Zendesk (2 lookups) + Salesforce (4 lookups) + SendGrid (3 lookups) + HubSpot (2 lookups) = 12 lookups, the record fails with `PermError`. Receivers stop reading the record and treat legitimate mail as unauthenticated.

#### 14. Automatic SPF CIDR Record Flattening Engine
* **What It Does**: Recursively resolves all nested `include:` domains down to raw `ip4:` and `ip6:` CIDR blocks, assembling an optimized zero-lookup record.
* **What It Tells You**: Provides a drop-in replacement SPF record with 0 DNS lookups.
* **Why It Is Important**: Eliminates the 10-lookup limit problem forever without removing any authorized cloud senders.

#### 15. DMARC Enforcement & Alignment Policy Scan (RFC 7489)
* **What It Does**: Queries `_dmarc.{domain}` and evaluates policy enforcement: `p=none` (monitoring), `p=quarantine` (deliver to spam), and `p=reject` (block at gateway), plus alignment flags (`adkim`, `aspf`).
* **What It Tells You**: Whether recipient mail servers actively block phishing emails or merely log them.
* **Why It Is Important**: `p=none` offers **zero protection** against spoofing. Attackers can still send phishing emails as your brand. Only `p=quarantine` and `p=reject` protect customers, employees, and partners from phishing.

#### 16. DMARC Aggregate (`rua`) & Forensic (`ruf`) Telemetry Scan
* **What It Does**: Verifies whether DMARC aggregate reporting URIs (`rua=mailto:...`) are configured.
* **What It Tells You**: Confirms whether the domain owner receives daily XML telemetry reports from Gmail, Microsoft, and Yahoo about who is attempting to send email as their domain worldwide.
* **Why It Is Important**: Without `rua`, IT administrators operate blind. They have no visibility into active phishing campaigns targeting their brand, nor do they know if a legitimate SaaS provider's emails are failing authentication.

#### 17. DKIM (DomainKeys Identified Mail) Multi-Selector Scan (RFC 6376)
* **What It Does**: Concurrently probes 15 industry-standard DKIM selectors (`google`, `default`, `s1`, `selector1`, `mail`, `k1`, `zendesk`, `amazonses`, `mandrill`, etc.) at `{selector}._domainkey.{domain}` and extracts RSA/Ed25519 public keys.
* **What It Tells You**: Validates whether cryptographic signatures are published and confirms which cloud providers sign outgoing messages.
* **Why It Is Important**: DKIM creates a cryptographic tamper-evident seal on outgoing emails. If an email is altered in transit (e.g. malicious invoice link substitution), the DKIM signature breaks and recipient servers flag the tampering.

#### Custom DKIM Selector Checks
* **What It Does**: Allows the user to submit up to 20 additional selector names for DNS TXT lookup, beyond the built-in common selector list.
* **What It Tells You**: Helps check selectors used by a particular mail provider or organization.
* **Limit**: A selector not found in DNS does not prove that a domain has no DKIM; selectors depend on the mail provider and signing configuration.

#### MTA-STS and TLS-RPT Mail Transport Checks
* **What It Does**: Checks `_mta-sts` and `_smtp._tls` DNS TXT records. If MTA-STS is published, it retrieves the policy file over validated HTTPS and summarizes its settings.
* **What It Tells You**: Reports whether a published policy file is reachable and whether TLS failure reporting destinations are configured.
* **Limit**: These checks inspect DNS and the policy file; they do not send email or prove that every sender enforces the policy.

---

### Category 3: Cryptography & Threat Defense Scans

#### 18. Subdomain Takeover Fingerprints
* **What It Does**: Checks CNAME targets against a local catalog of 10 provider patterns. For HTTP patterns, the scanner makes a pinned HTTPS request with redirects disabled, a short timeout, a 16 KiB response cap, and a shared per-scan request budget.
* **What It Tells You**: DNS-only evidence is a `candidate` by default. A bounded page-text match is also a candidate while the catalog entry is unverified. Only a verified entry can produce a confirmed page match, and only an explicitly opted-in verified NXDOMAIN rule can produce a confirmed DNS result; neither proves claimability.
* **Limit**: All 10 shipped entries are marked unverified and have NXDOMAIN confirmation disabled. The scanner uses a small heuristic fingerprint catalog; it does not provide CVE-based threat hunting.

#### 19. DNSSEC Inspection (RFC 4033, 4034, 4035)
* **Default behavior**: `ENABLE_DNSSEC_CHAIN_VALIDATION` is off. The live scan compares observed DNSKEY and DS records only. DNSKEY without parent DS is `incomplete_chain`; absent DNSKEY is `unsigned`; lookup or uncomparable DS data is `inconclusive`.
* **Opt-in behavior**: With the flag enabled, the response includes separate chain evidence in `chain_status` (`secure`, `insecure`, `bogus`, or `inconclusive`). The public `status` and score input remain the legacy result; chain results are informational and cannot change score, grade, or caps.
* **Limit**: The default legacy comparison does not validate RRSIGs or construct the complete root-to-domain trust chain. The opt-in chain engine remains disabled by default and its scoring rules await approval.

#### 20. BIMI (Brand Indicators for Message Identification) Check (RFC 8617)
* **What It Does**: Queries `default._bimi.{domain}` for a BIMI TXT record and checks whether the DMARC policy meets the configured eligibility criteria (`p=quarantine` or `p=reject` with `pct=100`).
* **Limit**: It does not fetch or validate the referenced SVG or VMC.
* **What It Tells You**: Confirms whether the company's verified brand avatar will display next to emails in Gmail, Apple Mail, and Yahoo Mail.
* **Why It Is Important**: BIMI may display a brand mark in supported mail clients. It is a visual indicator, not proof that a message is authentic.

#### 21. Remediation Suggestions & BIND Zone File Export
* **What It Does**: Creates draft DNS records and provider guidance for Cloudflare, Route 53, Namecheap, Hostinger, BigRock, Google Cloud DNS, and Azure DNS, plus a BIND zone snippet.
* **What It Tells You**: Suggested configuration values to review with the DNS provider before publishing; generated fixes are not automatically applied.
* **Why It Is Important**: A scanner that only reports errors creates friction. This feature bridges diagnosis and resolution, allowing administrators to harden their domain in under 60 seconds.

---

### Category 4: Web Security, Certificate Transparency & Scoped Network Audits

#### 22. Authoritative Zone Apex Discovery (RFC 1034, 2181)
* **What It Does**: Recursively traverses domain labels to locate the true authoritative zone cut (`SOA` / `NS`) prior to running zone-level checks.
* **What It Tells You**: Identifies whether the submitted target is an apex zone or a subdomain delegating to a parent zone, and isolates authoritative zone records accurately.
* **Why It Is Important**: Reduces false alarms for hostnames that inherit authority from a parent zone. Apex discovery is heuristic and does not replace checking delegation with the domain operator.

#### 23. TLS Encryption & HTTPS Security Posture Audit
* **What It Does**: Checks certificate validity, negotiated TLS details, HTTP-to-HTTPS behavior, and observed response headers. Header review includes HSTS, CSP risk notes, Permissions-Policy, COOP/CORP, and cookie flags. It also requests `/.well-known/security.txt` with a timeout and 16 KiB body cap, then checks that Contact is present and exactly one timezone-qualified Expires timestamp is valid and in the future. A safe `OPTIONS` request reports methods advertised in the `Allow` header.
* **What It Tells You**: Highlights certificate and browser-policy issues visible from the scanned endpoint. Cookie values are not retained. Advertised HTTP methods are hints, not proof that those methods accept requests; no write-method request is sent.
* **Why It Is Important**: Modern web applications must enforce end-to-end transport encryption. Missing HSTS allows SSL stripping attacks, and expired certificates trigger browser security warnings that destroy user trust.

#### 24. Passive Subdomain Inventory via Certificate Transparency (RFC 6962)
* **What It Does**: Queries public Certificate Transparency (CT) logs via `crt.sh` to extract publicly logged subdomains associated with the root apex, then non-intrusively resolves their IP addresses and inspects CNAME pointers.
* **What It Tells You**: Lists hostnames publicly logged in CT and the scanner's bounded DNS observations, including possible dangling CNAME candidates.
* **Limit**: CT discovery depends on a third-party CT lookup and is capped. DNS observations and provider fingerprints are heuristic; this is not a complete asset inventory.

#### 25. Scoped Network Inventory & SSRF-Guarded Port Auditing
* **What It Does**: Provides Nmap-style target scope resolution (List Scan) and scoped TCP port verification for standard services (HTTP 80, HTTPS 443, SSH 22, SMTP 25/465/587, DNS 53) with built-in SSRF protections.
* **What It Tells You**: Lists in-scope public targets and detects open listening services with banner grabbing and TCP SYN/ACK verification.
* **Why It Is Important**: Enforces strict SSRF defense by disallowing probes against loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), ensuring the tool cannot be weaponized to map internal networks.

#### 25. Optional Common Web Path and Publication-File Review
* **What It Does**: Checks a bounded list of common paths, then may read same-origin `robots.txt` and sitemap files to identify referenced paths. It follows only permitted same-host redirects and limits the number of sitemap references checked.
* **What It Tells You**: Shows public responses and paths intentionally listed in publication files. Names that look sensitive are labeled for manual review; the tool does not attempt authentication or access-control bypass.
* **Limit**: This is not directory brute forcing or recursive crawling. A listed path is not necessarily sensitive, and a response status alone does not establish an exposure.

#### 26. Scan Coverage, Browser-Local History, and Exports
* **What It Does**: The coverage panel reports completed, partial, blocked, and optional checks. Browser-local history compares DNS records and, when both samples are complete, CT names; it can also compare certificate and optional path results. CT subdomains can be exported as CSV.
* **Privacy**: History snapshots are stored in the current browser's local storage and can be cleared from the dashboard. They are not a server-side monitoring service.
* **Reports**: The standalone HTML report includes available scan findings and coverage information; recent path scan results may be included when available.

#### Privacy, outbound requests, and budgets

Use this scanner only for domains and hosts you own or are authorized to assess. Python logs go to the default stream; log destination and retention are **not configured by the application**. Uvicorn access logs are enabled by default in `run.sh` and Docker and include client IP, method, request path (including domains on subdomains/report/badge routes), and response status. Application logs include domain names on scan/report/subdomain failures, exception diagnostics, failed module names, DNS query types, TLS verification messages, and unknown finding codes. `httpx` may log outbound request URLs at INFO. The port-token deprecation warning never records the token; request bodies and client IPs are not written by application logger calls. API errors, including validation errors, use generic text. There is no persistent server-side result store: scan cache 60 seconds (up to 128 domains), path results 15 minutes (up to 128 targets), custom DKIM results 15 minutes (up to 128 domain/selector-set entries), and badge SVGs only while the related scan is fresh (up to 256 entries). The process-local rate limiter stores client IP keys and timestamps (up to 2,048 client entries); its destination and retention are not configured by the application. Browser local storage keeps up to five recent domains and up to 60 snapshots (five per domain), with no application-configured expiry.

DNS queries go to the recursive resolver configured on the application host. CT discovery submits the domain to `crt.sh`; web/TLS and MTA-STS requests go to the scanned host or its relevant policy/CNAME hosts. Third-party retention is outside application control. Outbound HTTP identifies itself as `DNSAnalyzer/2.2.0 (+<documentation URL>)`; set `DNS_ANALYZER_DOCUMENTATION_URL` to replace the placeholder. Per-scan limits are 500 DNS queries and 25 HTTP fetches. Full scans reserve shares per module; standalone network diagnostics receive their own per-request allocation. Exhausted checks are inconclusive.

---

## 7. RFC Rules & Security Standards Reference

| Category | RFC Standard | Rule Function / Inspection Scope | Severity |
|:---|:---|:---|:---|
| **Routing** | RFC 1035 | `check_domain_resolves`: Validates domain resolves to IPv4 or IPv6 | **ERROR** |
| **Routing** | RFC 1034 / 1035 | `check_ns_exists`: Verifies authoritative nameservers exist | **ERROR** |
| **Routing** | RFC 1035 §2.2 | `check_ns_redundancy`: Enforces minimum of 2 distinct nameservers | **WARNING** |
| **Routing** | RFC 1035 | `check_ns_resolves`: Verifies each nameserver host resolves to an IP | **ERROR** |
| **Email** | RFC 5321 | `check_mx_exists`: Verifies mail exchange records are published | **INFO** |
| **Email** | RFC 5321 | `check_mx_resolves`: Verifies mail hosts have address records; it does not connect to them | **ERROR** |
| **DNS Rules** | RFC 1034 §3.6.2 | `check_cname_conflict`: Ensures CNAME exclusivity at zone node | **ERROR** |
| **Operations**| RFC 1912 / 2182 | `check_soa_sanity`: Audits SOA refresh, retry, and expire sanity | **WARNING** |
| **Operations**| RFC 1035 | `check_ttl_sanity`: Flags `TTL = 0` and `TTL > 7 days` | **WARN/INFO** |
| **Anti-Spoof**| RFC 7208 | `check_spf_policy`: Checks for `v=spf1`, flags `+all` and weak `?all` | **ERROR/WARN**|
| **Anti-Spoof**| RFC 7208 §3.2 | `check_spf_multiple`: Flags duplicate SPF records causing PermError | **ERROR** |
| **Anti-Spoof**| RFC 7208 §4.6.4| `check_spf_lookup_limit`: Recursive 10-lookup count & tree audit | **ERROR/WARN**|
| **Anti-Spoof**| RFC 7208 §5.5 | `check_spf_deprecated_ptr`: Flags deprecated and slow `ptr` mechanism| **WARNING** |
| **Phishing** | RFC 7489 | `check_dmarc_policy`: Audits `none` → `quarantine` → `reject` & `rua` | **ERROR/WARN**|
| **Signatures**| RFC 6376 | `check_dkim_selectors`: Audits 15 selectors & public key extraction | **INFO/WARN** |
| **Takeover** | Service fingerprints | `check_subdomain_takeover`: Unverified page matches and default DNS-only evidence are candidates; confirmation requires verified catalog data and explicit opt-in | **WARN/ERROR** |
| **Crypto** | RFC 4033–4035 | `check_dnssec`: validates DNSKEY, DS and SOA signatures from root anchors; denial proofs are not validated | **INFO/WARN/ERROR** |
| **Branding** | RFC 8617 | `check_bimi`: SVG logo publication & DMARC eligibility | **INFO** |
| **Zone Cut** | RFC 1034/2181 | `discover_zone_apex`: Authoritative zone tree cut discovery | **INFO** |
| **Web Security** | RFC 5246/8446 | `audit_tls_and_https`: Certificate expiration, TLS 1.3 & HSTS | **WARN/INFO** |
| **Recon** | RFC 6962 | `discover_passive_subdomains`: CT log discovery & dangling CNAMEs | **INFO/ERROR**|
| **SSRF Guard** | RFC 1918/6890 | `is_safe_public_ip`: Blocks loopback & private RFC 1918 subnets | **ERROR** |
| **Network** | RFC 793/1122 | `scan_target_standard_ports`: Non-blocking TCP port auditing | **INFO** |

---

## 8. Comprehensive Interview & Viva Q&A

### Category A: Core Concepts & Motivation
* **Q: What is the primary purpose of this project?**  
  *Answer:* To automate comprehensive DNS infrastructure health auditing, email spoofing defense evaluation, and cryptographic security verification into a fast, non-blocking web platform that provides immediate diagnostic answers and copy-paste remediation rather than raw, cryptic command-line output.
* **Q: Why is DNS misconfiguration dangerous to businesses?**  
  *Answer:* DNS is the single point of failure for all internet services. A lack of nameserver redundancy can take down an entire digital presence; an unresolvable MX host drops critical business emails; a dangling CNAME allows attackers to take over subdomains; and a missing or weak SPF/DMARC policy allows cybercriminals to forge executive emails to steal money or credentials.

---

### Category B: Concurrency, Performance & Architecture
* **Q: Why use `asyncio.gather` instead of sequential lookups?**  
  *Answer:* DNS lookups are network I/O-bound. Running 7 DNS queries + SPF + DMARC + 15 DKIM selectors sequentially at ~150ms per network round-trip takes **3 to 4 seconds**. With `asyncio.gather`, all queries execute concurrently on Python's event loop, completing in the time of the single slowest lookup (~150ms total), achieving a **15x to 20x performance speedup**.
* **Q: Why Vanilla JavaScript instead of React, Next.js, or Vue?**  
  *Answer:* The browser interface is plain HTML, CSS, and JavaScript, so it needs no frontend build step or Node.js toolchain. The Python backend still installs its runtime dependencies.

---

### Category C: Email Defense & SPF Flattening
* **Q: What is SPF Record Flattening and how does your engine implement it?**  
  *Answer:* RFC 7208 strictly limits SPF evaluation to 10 DNS lookups to prevent Denial of Service loops. Enterprises integrating multiple SaaS platforms (Google, Zendesk, Salesforce, SendGrid) easily exceed 10 lookups, causing receivers to return `PermError` and reject emails. Our flattener recursively follows all `include:` and `redirect=` domains, resolves their underlying A/AAAA records into direct CIDR IP blocks (`ip4:` and `ip6:`), and outputs an optimized replacement record requiring exactly **0 DNS lookups**.
* **Q: What is the difference between DMARC `none`, `quarantine`, and `reject`?**  
  *Answer:*
  - `p=none`: Audit mode. Unauthorized emails are delivered normally to recipient inboxes; only XML telemetry reports are generated. Does not stop phishing.
  - `p=quarantine`: Moderate enforcement. Unauthorized emails are routed to the recipient's Spam/Junk folder.
  - `p=reject`: Requests receivers to reject messages that fail DMARC policy evaluation. Receiver behavior can vary, and this does not prevent every form of phishing or spoofing.
* **Q: How is the posture score computed?**
  *Answer:* The weighted factors are DNS infrastructure (20), email authentication (25), DNSSEC (20), takeover evidence (15), TLS/web (10), mail transport (5), and DNS posture (5). Not-applicable factors and wholly inconclusive factors are excluded; remaining weights are normalized to 100. In partially observed factors, inconclusive checks receive neutral 50% credit. The breakdown reports check states and scoring policy. The label reports `based on X of Y factors`. When excluded weight is over 30%, the grade is marked `(incomplete)`. AXFR caps at 54; confirmed takeover and bogus DNSSEC cap at 39 each. Grade bands remain A+ (95–100), A (85–94), B (70–84), C (55–69), D (40–54), and F (<40).

---

### Category D: Takeover Indicators & Cryptography
* **Q: What is a subdomain takeover and what does this scanner establish?**
  *Answer:* A risk can arise when a CNAME points to a third-party resource that is no longer controlled by the domain owner and can be claimed by another account. All current catalog entries are unverified, so their page-text matches and default DNS-only evidence remain candidates. Confirmation requires a verified entry and its configured confirmation method; even then, the scanner does not prove provider-side claimability.
* **Q: What does the current DNSSEC check validate?**
  *Answer:* By default it compares DNSKEY and DS records without signature validation. The opt-in chain engine returns its state as informational `chain_status`; scoring still uses the legacy delegation result. DS denial is not authenticated yet.

---

### Category E: UI/UX & Design Engineering
* **Q: What design principles make your Bento Grid superior to traditional tables?**  
  *Answer:* It applies the Two-Tier Cognitive Model:
  1. *Tier 1 (Executive Cockpit)*: The left hero card with the circular health ring answers the user's primary question in 3 seconds: "Am I secure and what is broken?"
  2. *Tier 2 (Actionable Telemetry)*: The 2×2 grid groups metrics into logical pillars (DNS, Email, Cryptography, Remediation) with zero text truncation, live status dots, and direct jump navigation.

---

### Category F: Reliability & Code Quality
* **Q: What supports runtime reliability?**
  *Answer:* The repository includes unit and integration tests runnable under `pytest`; many network-facing code paths use mocks for deterministic checks. `run.sh` prepares the virtual environment and launches the application. Compatibility still depends on the Python versions and dependency ranges documented by the project.

---

### Category G: Active/Passive Reconnaissance, Network Audits & SSRF Defense
* **Q: Why is SSRF protection critical when building network diagnostic tools?**  
  *Answer:* Web diagnostic tools that accept user-provided hostnames or IP addresses can be abused by attackers as an open proxy or Server-Side Request Forgery (SSRF) vector to probe internal infrastructure (e.g. AWS metadata `169.254.169.254`, Kubernetes services, Docker networks, or private database ports `10.0.0.0/8`, `192.168.0.0/16`). Our engine uses `ipaddress.ip_network` boundaries to strictly disallow loopback, link-local, multicast, and RFC 1918 private subnets prior to initiating any TCP connections.
* **Q: How does passive subdomain enumeration differ from active brute-forcing?**  
  *Answer:* Passive CT discovery queries a public certificate-log service over HTTPS. The CT query itself does not probe the target web server; discovered hostnames may then be resolved through DNS as part of the inventory workflow.
* **Q: Why must authoritative zone discovery happen before checking NS, SOA, and DNSSEC?**  
  *Answer:* When scanning subdomains like `app.dashboard.company.com`, checking NS or SOA at the leaf node directly will fail because subdomains do not typically possess independent zone apex authority unless delegated. Traversing upward to locate the authoritative SOA cut ensures the diagnostic engine evaluates the true responsible nameservers without issuing false-alarm security warnings.

---

## 9. Pro Tips to Impress Teachers & Evaluators

1. **Demonstrate Headless CI/CD Capabilities with `curl`:**  
   Open a second terminal and demonstrate that your system is a headless REST API ready for enterprise pipelines:
   ```bash
   curl -s -X POST http://127.0.0.1:8000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"domain":"google.com"}' | python3 -m json.tool | head -35
   ```
2. **Demonstrate Mouse-Free Keyboard Navigation:**  
   Press `/` to focus the search bar, enter a domain, press <kbd>Enter</kbd>, press `f` to cycle severity filters, and press `v` to switch between Card View and the CLI `dig` terminal.
3. **Showcase the Standalone Offline Report:**  
   Click **Download Report** and open the `.html` file directly from your local file browser (`file:///...`). Highlight that all styles are embedded inline and it functions without an internet connection or backend server.
4. **Contrast with Traditional CLI `dig`:**  
   Explain that gathering this breadth of information manually requires executing 10+ distinct `dig` commands, 3 recursive lookup trees, manual RFC arithmetic, and deep cryptographic validation.

---

## 10. Closing Statement

> *"DNS Analyzer 2.2.0 brings DNS and email checks, selected TLS and web diagnostics, known-pattern takeover checks, and remediation guidance into one dashboard. Its coverage panel shows where checks are incomplete, so teams can use the results as a starting point for investigation. Thank you."*

---

## 11. Quick Start & Scripts

| Script Command | Purpose |
|:---|:---|
| `bash run.sh` | **Recommended:** Auto-setup environment, verify dependencies, and launch server on `http://127.0.0.1:8000` |
| `bash run.sh <port>` | Launch server on custom port (e.g. `bash run.sh 9000`) |
| `bash run.sh --docker` | **Docker v2:** Build and run containerized multi-stage service via Docker |
| `bash run.sh --test` | Run the automated test suite |
| `bash run.sh --setup-only` | Pre-install dependencies and prepare `venv/` without launching server |
| `./venv/bin/dns-analyzer example.com` | Run the shared scan pipeline from the CLI |
| `./venv/bin/dns-analyzer example.com --json` | Print machine-readable scan JSON |
| `./venv/bin/dns-analyzer example.com --min-grade B` | Compare by base letter; provisional grades warn. Code 2 means below B; code 3 means error findings |
| `./venv/bin/dns-analyzer example.com --require-complete` | Exit with code 4 if the grade is provisional; error findings still return code 3 |
| `docker run -d -p 8000:8000 kanishkchahar/dns-analyzer:v2.2.0` | Run the versioned production image directly via Docker |
| `bash run.sh --help` | Display command usage and script flags |
