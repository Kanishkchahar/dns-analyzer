# 🛡️ DNS Analyzer v2 (InboxShield Edition)
## Master Presentation, Demo Script & Technical Viva Reference

> **Project Author:** Kanishk  
> **Version:** 2.0 — InboxShield Edition  
> **Tech Stack:** Python 3.11+ · FastAPI · dnspython · Vanilla JS · Jinja2 · Uvicorn  

---

## 📑 Table of Contents
1. [Elevator Pitch & Opening Statement](#1-elevator-pitch--opening-statement)
2. [Live Demonstration Script (2–3 Minutes)](#2-live-demonstration-script-23-minutes)
3. [Executive Summary & Problem Statement](#3-executive-summary--problem-statement)
4. [Tech Stack & Architectural Justifications](#4-tech-stack--architectural-justifications)
5. [System Architecture & Concurrency Workflow](#5-system-architecture--concurrency-workflow)
6. [RFC Rules & Security Standards Reference](#6-rfc-rules--security-standards-reference)
7. [Comprehensive Interview & Viva Q&A (Categories A–E)](#7-comprehensive-interview--viva-qa)
8. [Pro Tips to Impress Teachers & Evaluators](#8-pro-tips-to-impress-teachers--evaluators)
9. [Closing Statement](#9-closing-statement)
10. [Quick Start](#10-quick-start)

---

## 1. Elevator Pitch & Opening Statement

> *"Good morning / afternoon. Today, I am presenting **DNS Analyzer v2 — InboxShield Edition**.*  
> *DNS is the phonebook and foundational backbone of the internet, while email authentication is the frontline defense against phishing and spoofing. Misconfigured DNS zones silently bring down websites, drop critical emails, and expose companies to cyberattacks.*  
>  
> *Traditional CLI tools like `dig` or `nslookup` require running multiple commands sequentially and manual expert interpretation. I built a modern, asynchronous web platform that audits all 7 major DNS record types in parallel, evaluates 15+ RFC compliance checks, audits SPF, DMARC, and DKIM email security, and produces an instant letter-graded diagnostic report — in under 2 seconds."*

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
| **1** | `cloudflare.com` (or click Quick Chip) | **Enterprise Best Practice:** Score **A+**. Fully secured DNSSEC (ECDSA), Active BIMI logo, Subdomain Takeover protected, and strong DMARC policy. |
| **2** | `google.com` | **Email Scale:** Strict DMARC enforcement, strong SPF, and multiple verified DKIM selectors. |
| **3** | `https://www.boot.dev/dashboard` | **Automatic URL Extraction:** Paste the full URL. Watch the frontend extract the hostname `boot.dev` automatically with zero user cleanup required. |
| **4** | `example.com` | **Remediation Wizard:** Shows missing email auth, with the **1-Click DNS Fix Generator** generating exact Cloudflare/AWS Route 53 records and exportable BIND zone file! |
| **5** | `invalid!!!domain` | **Resilience & Validation:** Pydantic regex rejects bad input instantly with clean HTTP 400 error banner — no server crashes. |

### Key Features to Call Out During the Demo:
1. ⚡ **Concurrent Lookups**: *"All 7 DNS record types + SPF + DMARC + DKIM + DNSSEC + Subdomain Takeover + BIMI return concurrently in under 200ms using `asyncio.gather` — zero sequential waiting."*
2. 📊 **Email Health Score Ring**: *"The animated circular SVG ring computes a weighted score (0–100) and assigns an A+ to F grade based on real RFC compliance."*
3. 🛡️ **Subdomain Takeover Defense**: *"Detects dangling CNAME records pointing to abandoned AWS S3, GitHub Pages, Heroku, or Shopify endpoints before attackers hijack them."*
4. 🔐 **DNSSEC Cryptographic Chain**: *"Audits Zone Signing Keys (ZSK), Key Signing Keys (KSK), and parent DS delegations to protect against DNS cache poisoning."*
5. ✨ **BIMI Brand Certification**: *"Checks whether the domain qualifies to display its verified brand logo in Gmail and Apple Mail customer inboxes."*
6. 🔧 **1-Click Remediation & BIND Zone File**: *"Not just a scanner — an actionable solution. Generates exact copy-paste DNS records for Cloudflare, Route 53, and GoDaddy with an instant BIND zone file export."*
7. 🎛️ **Interactive Severity Filters**: *"Click 'Errors', 'Warnings', or 'Info' badges to filter the diagnostic findings instantly without page reloads."*
8. 📈 **SPF Lookup Meter Bar**: *"Visual meter displaying real-time lookups against RFC 7208 limit of 10 with automatic flattening recommendations."*
9. 📥 **Offline Download Report**: *"Single-file standalone report with all CSS embedded, opening completely offline."*
10. ♿ **Radical Ease of Access**: *"Keyboard-first navigation (`/`, `?`, `1-4`, `f`, `d`), persistent search history, URL auto-sanitization, and plain-English tooltips for non-technical users."*

---

## 2.1 GUI Ease of Access & Presentation Walkthrough

When presenting this website to users, teachers, or evaluators, focus on **"Radical User Ease of Access"**. Explain how DNS Analyzer bridges the gap between deep infrastructure complexity and consumer-grade usability:

```
Traditional CLI (dig / nslookup)           DNS Analyzer v2 (Ease of Access)
─────────────────────────────────          ─────────────────────────────────
• Requires terminal & command syntax       • Zero install, clean browser UI
• Must run 7–10 commands per domain        • 1-click concurrent audit in <200ms
• Outputs cryptic raw DNS zone text        • Visual color-coded health grades (A+ to F)
• Leaves users clueless how to fix bugs    • 1-Click copyable DNS fixes & BIND zone file
• Fails on dirty URLs                      • Auto-extracts hostname from any URL
• Mouse-only or CLI-only                   • Full keyboard accessibility (`/`, `?`, `1-4`, `f`, `d`)
```

### The 5 Ease-of-Access Talking Points to Deliver:

1. **Zero-Barrier Input & URL Hygiene**:
   > *"Users don't need to know domain syntax. You can paste dirty strings like `https://boot.dev/dashboard?ref=test` and the frontend regex automatically cleans it to `boot.dev`. Plus, returning users have their recent searches saved locally in 1-click history chips."*

2. **Full Keyboard-Driven Accessibility (WCAG Compliant)**:
   > *"Power users and screen-reader users can operate the entire platform without touching a mouse. Pressing `/` jumps to search, `1` through `4` test sample domains, `f` cycles findings severity filters, `d` triggers report downloads, and `?` opens our comprehensive shortcuts modal."*

3. **Cognitive Clarity Over Information Overload**:
   > *"Instead of bombarding non-technical administrators with cryptic RFC error codes, we provide plain-English 'What is this?' info badges (`?`) across SPF, DMARC, DKIM, DNSSEC, and BIMI. The circular SVG health ring translates complex security posture into an immediate letter grade (A+ through F)."*

4. **Visual Transparency & Live Progress**:
   > *"During analysis, an animated micro-status bar informs the user in real time about concurrent operations (`Querying 7 record types... Auditing SPF... Inspecting DNSSEC...`), eliminating user friction and perceived wait times."*

5. **Actionable 1-Click Resolution**:
   > *"Ease of access isn't just about reading data — it's about solving problems effortlessly. Our 1-Click DNS Fix Generator provides tailored copy-paste snippets for Cloudflare, Route 53, and GoDaddy, plus an exportable standard BIND zone file."*

---

## 3. Executive Summary & Problem Statement

### The Problem:
* **72% of organizations** experience DNS-related outages (EfficientIP Global DNS Threat Report).
* **91% of cyberattacks** start with email spoofing or phishing (FBI IC3).
* Standard diagnostic utilities (`dig`, `nslookup`) are:
  - Single-query only (must run 7–10 commands per domain).
  - Terminal-only and unstandardized.
  - Incapable of automated policy evaluation or recursion tracking.

### The Solution:
DNS Analyzer automates full-zone inspection, email security assessment, and RFC compliance auditing into a clean zero-dependency web interface.

---

## 4. Tech Stack & Architectural Justifications

| Component | Technology | Rationale & Why It Beats Alternatives |
|:---|:---|:---|
| **Backend Framework** | **FastAPI** (Python 3.11+) | Native `async`/`await` support for high concurrency event loops. Automatic Pydantic schema validation and OpenAPI serialization. Outperforms Flask and Django for I/O-bound networking. |
| **ASGI Server** | **Uvicorn** | High-performance asynchronous server built on `uvloop` and `httptools`. Minimal memory footprint with multi-worker scaling. |
| **DNS Engine** | **dnspython** (`dns.asyncresolver`) | The industry-standard Python DNS library. Provides non-blocking async query methods, raw RRset inspection, TTL extraction, and granular exception handling (`NXDOMAIN`, `NoAnswer`, `Timeout`). |
| **Frontend UI** | **Vanilla HTML5 + Modern CSS + ES6+ JS** | **Zero build step, zero npm dependencies, zero node_modules.** Loads in milliseconds, zero supply-chain attack surface, accessible ARIA live regions, Geist design tokens. |
| **Report Engine** | **Jinja2** | Generates self-contained single-file HTML reports with inlined CSS for offline portability. |
| **Runner Script** | **Unified `run.sh`** | Combines dependency verification, self-healing venv rebuilding, and server launching in one command. |

---

## 5. System Architecture & Concurrency Workflow

```
               ┌───────────────────────────────────────────┐
               │         Browser UI (Vanilla JS)           │
               │  Quick chips / Keyboard shortcuts (/)     │
               └─────────────────────┬─────────────────────┘
                                     │ POST /api/analyze
                                     ▼
               ┌───────────────────────────────────────────┐
               │        FastAPI Gateway (app/main.py)      │
               │     Strict Pydantic Domain Validation     │
               └─────┬───────────────┬───────────────┬─────┘
                     │               │               │
                     ▼               ▼               ▼
           ┌──────────────────┐ ┌─────────┐ ┌────────────────┐
           │ Async Resolver   │ │ SPF     │ │ DMARC & DKIM   │
           │ 7 Record Types   │ │ Parser  │ │ Multi-Selector │
           │ (asyncio.gather) │ │ Flatten │ │ Concurrent     │
           │ [A, AAAA, MX,    │ │ Counter │ │ Scan (15 hosts)│
           │  NS, TXT, CNAME, │ │ (spf.py)│ │ (email_auth.py)│
           │  SOA]            │ └────┬────┘ └───────┬────────┘
           └─────────┬────────┘      │              │
                     └───────────────┼──────────────┘
                                     ▼
               ┌───────────────────────────────────────────┐
               │          RFC Rule Analysis Engine         │
               │  - 9 Infrastructure checks (analyzer.py)  │
               │  - SPF 10-lookup & policy (spf.py)        │
               │  - DMARC enforcement & rua (email_auth.py)│
               │  - DKIM key validity (email_auth.py)      │
               │  - Weighted Email Health Score (0-100)    │
               └─────────────────────┬─────────────────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
       ┌───────────────────────────┐   ┌───────────────────────────┐
       │   JSON Dashboard Stream   │   │  Self-Contained Report    │
       │   Filters + Meter Bar     │   │  Jinja2 Offline HTML      │
       └───────────────────────────┘   └───────────────────────────┘
```

---

## 6. RFC Rules & Security Standards Reference

### Core DNS Infrastructure Checks:
1. **RFC 1035 (`check_domain_resolves`)**: Domain resolves to at least one valid IPv4 (`A`) or IPv6 (`AAAA`) record. *(Severity: ERROR)*
2. **RFC 1034 / 1035 (`check_ns_exists`)**: Authoritative Nameserver records exist for the zone. *(Severity: ERROR)*
3. **RFC 1035 §2.2 (`check_ns_redundancy`)**: At least 2 distinct nameservers exist to eliminate Single Points of Failure. *(Severity: WARNING)*
4. **RFC 1035 (`check_ns_resolves`)**: Each authoritative NS host resolves to an IP address. *(Severity: ERROR)*
5. **RFC 5321 (`check_mx_exists`)**: MX records present for mail-handling domains. *(Severity: INFO)*
6. **RFC 5321 (`check_mx_resolves`)**: Mail exchange hosts resolve to reachable `A` records to prevent email bounce-backs. *(Severity: ERROR)*
7. **RFC 1034 §3.6.2 & RFC 2181 (`check_cname_conflict`)**: Verifies CNAME does not coexist with other record types at the same node. *(Severity: ERROR)*
8. **RFC 1912 / 2182 (`check_soa_sanity`)**: Validates SOA parameters (`refresh >= retry`, `expire >= 172,800s / 2 days`). *(Severity: WARNING)*
9. **RFC 1035 (`check_ttl_sanity`)**: Flags `TTL = 0` (kills caching) and `TTL > 7 days` (prevents emergency IP failover). *(Severity: WARN/INFO)*

### Email Authentication & Anti-Spoofing Checks:
10. **RFC 7208 (`SPF Policy`)**: Checks for `v=spf1`, flags dangerous `+all` (anyone can spoof) and weak `?all` policies.
11. **RFC 7208 §3.2 (`Multiple SPF Records`)**: Flags duplicate SPF records which cause receivers to return `PermError`.
12. **RFC 7208 §4.6.4 (`SPF 10-Lookup Limit`)**: Recursively counts lookups. Warns at 8–10 lookups; raises an ERROR at >10. Provides automated flattened SPF generation.
13. **RFC 7208 §5.5 (`Deprecated PTR`)**: Flags deprecated `ptr` mechanism.
14. **RFC 7489 (`DMARC Evaluation`)**: Checks `_dmarc.{domain}` for `p=none` (monitoring only), `p=quarantine`, and `p=reject` (full enforcement), plus `rua` reporting and `pct` coverage.
15. **RFC 6376 (`DKIM Verification`)**: Concurrently scans 15 common selectors (`google`, `default`, `s1`, `mail`, `k1`, etc.), extracting public keys and checking test flags (`t=y`).

---

## 7. Comprehensive Interview & Viva Q&A

### Category A: Core Concepts
* **Q: What is the primary purpose of this project?**  
  *Answer:* To automate domain DNS health verification and email spoofing defense analysis into a fast, non-blocking web platform that provides immediate diagnostic answers rather than raw manual output.
* **Q: Why is DNS misconfiguration dangerous?**  
  *Answer:* It can cause total site downtime (lack of NS redundancy), dropped emails (unresolvable MX hosts), and security breaches (dangling CNAME takeovers, email domain spoofing).

### Category B: Technical Implementation & Concurrency
* **Q: Why use `asyncio.gather` instead of standard sequential lookups?**  
  *Answer:* Querying 7 DNS record types sequentially with network round-trips (~150ms each) takes over 1 second. With `asyncio.gather`, all queries execute concurrently on Python's event loop, finishing in the time of the single slowest lookup (~150ms total), achieving a **7x speedup**.
* **Q: Why Vanilla JS over React/Angular?**  
  *Answer:* The application does not require heavy state stores. Vanilla JS gives instantaneous load times, zero build pipeline, zero node_modules, and zero supply chain vulnerabilities.

### Category C: Email Authentication & Security
* **Q: What is SPF Record Flattening?**  
  *Answer:* RFC 7208 limits SPF queries to 10 DNS lookups. Enterprises using multiple SaaS providers easily exceed 10 lookups, causing emails to be rejected (`PermError`). SPF flattening recursively resolves all `include:` and `redirect=` domains into direct `ip4:` and `ip6:` CIDR blocks, reducing DNS lookups to exactly **zero**.
* **Q: What is the difference between DMARC `none`, `quarantine`, and `reject`?**  
  *Answer:* `p=none` is audit mode (reports only, no delivery impact). `p=quarantine` moves failed messages to Spam. `p=reject` blocks unauthorized messages at the SMTP gateway.
* **Q: How does the Email Health Score calculate?**  
  *Answer:* It begins at 100 points, deducting 15 points per ERROR (e.g., missing SPF/DMARC) and 8 points per WARNING (e.g., weak policy, lookup count approaching 10). Clamped to 0–100 and mapped to A+, A, B, C, D, or F.

### Category D: System Operations & Self-Healing
* **Q: How does `run.sh` ensure reliability across different environments?**  
  *Answer:* It validates Python 3.11+, detects architecture-corrupted or invalid virtual environments, automatically rebuilds `venv/` if broken, verifies required packages, and validates port boundaries before starting Uvicorn.

---

## 8. Pro Tips to Impress Teachers & Evaluators

1. **Show the REST API via `curl` in a second terminal:**
   ```bash
   curl -s -X POST http://127.0.0.1:8000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"domain":"google.com"}' | python3 -m json.tool | head -40
   ```
   *Demonstrates that your platform is a modular, headless backend that can integrate into CI/CD pipelines.*
2. **Demonstrate Keyboard Shortcut (`/`):**
   *Press `/` from anywhere on the webpage to instantly jump focus into the domain input.*
3. **Open the Downloaded Offline HTML Report:**
   *Show that all styles are embedded inline; it opens directly from the filesystem without any local server running.*
4. **Compare against manual `dig`:**
   *Mention that getting the same level of diagnostic data manually requires 9 `dig` queries, 2 recursive lookups, and manual cross-referencing against RFC documents.*

---

## 9. Closing Statement

> *"DNS Analyzer v2 bridges the gap between low-level networking and security analysis. It delivers enterprise-grade diagnostics — from DNS zone integrity to email authentication — in a lightweight, accessible, zero-dependency package. Thank you. I would be happy to take any questions."*

---

## 10. Quick Start

```bash
# Navigate to project
cd ~/Desktop/dns-analyzer

# One-command setup & launch:
bash run.sh

# Or run on custom port:
bash run.sh 9000

# Open in browser:
# http://127.0.0.1:8000
```
