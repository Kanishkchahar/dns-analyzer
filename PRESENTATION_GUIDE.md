# 🛡️ DNS Analyzer v2 — InboxShield Edition
## Presentation Guide & Viva Reference

> **Project by:** Kanishk
> **Version:** 2.0 — InboxShield Edition
> **Stack:** Python · FastAPI · dnspython · Vanilla JS · Jinja2

---

## 🎯 Opening Statement (Use This to Start)

> *"I built DNS Analyzer — a real-time, asynchronous web application that performs complete DNS health diagnostics AND email authentication security analysis for any domain on the internet. It scans all 7 DNS record types simultaneously, runs 15+ RFC-based compliance checks, analyzes SPF, DMARC, and DKIM email security — and generates a downloadable offline report — all in under 2 seconds."*

---

## 📋 Presentation Flow — Step by Step

### Step 1: The Problem (30 seconds)

Say this:
> "DNS is the phonebook of the internet. When it's misconfigured, websites go down, emails get lost, and domains become vulnerable to spoofing attacks. Traditional tools like `dig` and `nslookup` only check one record at a time and give raw output that's hard to interpret. There's no automated diagnostic — you need a human expert. I built a tool that automates all of that."

**Key stats to drop:**
- 72% of organizations have experienced DNS-related outages (EfficientIP report)
- Email spoofing/phishing accounts for 91% of all cyberattacks (FBI IC3)
- A single misconfigured MX record can silently drop all incoming emails

---

### Step 2: Live Demo (2-3 minutes) ⭐ THIS IS THE MOST IMPORTANT PART

```bash
# Start the server
bash start.sh

# Open browser → http://127.0.0.1:8000
```

**Demo these domains in this order:**

| Domain | Why It's Impressive |
|--------|-------------------|
| `google.com` | Shows a well-configured domain — strong SPF, DMARC reject, DKIM keys found. Score: A+ |
| `boot.dev` | Good example of a modern site. Show how URL extraction works with `https://www.boot.dev/dashboard` |
| `example.com` | Simple domain — shows how missing email auth gets flagged |
| Any random small website | Often has misconfigurations — real-world proof the tool works |

**During the demo, point out:**
1. ⚡ **Speed** — "Notice how all records load in under 1 second — that's because I use `asyncio.gather` to query all 7 record types in parallel, not sequentially"
2. 📊 **Email Health Score Ring** — "This animated SVG score ring grades the domain from F to A+ based on SPF, DMARC, and DKIM analysis"
3. 🔴🟡🔵 **Color-coded findings** — "Red = errors, yellow = warnings, blue = informational. Each finding references a specific RFC standard"
4. 📧 **Email Auth Cards** — "SPF shows the policy and DNS lookup count against the RFC 7208 limit of 10. DMARC shows the policy strength. DKIM shows discovered selectors and key validity"
5. 📥 **Download Report** — Click it and open the downloaded HTML file — "This is a completely self-contained offline report with all CSS embedded. Security teams can email this around without needing server access"

---

### Step 3: Architecture Explanation (1-2 minutes)

Show this flow:

```
┌──────────────────────────────────────────────────────────────────┐
│                     User Browser (Frontend)                      │
│  Enter domain → auto-extract hostname from URLs → POST request   │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                    POST /api/analyze
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                 FastAPI Backend (main.py)                         │
│  Pydantic regex validation → reject bad domains with 400 error   │
└────────────────────────────┬─────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌──────────────┐ ┌───────────┐ ┌───────────────┐
     │  DNS Resolver │ │    SPF    │ │ DMARC + DKIM  │
     │  7 queries   │ │  Parser   │ │  Concurrent   │
     │  concurrent  │ │  Counter  │ │  Selectors    │
     └──────┬───────┘ └─────┬─────┘ └───────┬───────┘
            │               │               │
            └───────────────┼───────────────┘
                            ▼
     ┌──────────────────────────────────────────────────┐
     │           Rule Analyzer Engine                    │
     │  9 DNS checks + SPF + DMARC + DKIM analysis      │
     │  → Email Health Score (0-100, A+ to F)            │
     └──────────────────────┬───────────────────────────┘
                            ▼
     ┌──────────────────────────────────────────────────┐
     │  JSON Response → Frontend Dashboard              │
     │  OR                                              │
     │  Jinja2 → Self-contained HTML Report Download    │
     └──────────────────────────────────────────────────┘
```

---

### Step 4: Technical Highlights to Mention

#### 🚀 "Why is it fast?"
> "I use `asyncio.gather` for non-blocking concurrent I/O. Instead of querying 7 DNS record types one by one (7 × 150ms = 1+ second), all queries run in parallel and complete in ~150ms — a **7x speedup**. DMARC and DKIM checks also run concurrently."

#### 🔒 "How does SPF analysis work?"
> "SPF tells email servers which IP addresses are allowed to send email for a domain. My tool parses the SPF record, recursively traverses all `include:` chains, counts DNS lookups against the RFC 7208 limit of 10, and can even **flatten** the record into direct IP ranges if it exceeds the limit."

#### 📧 "How does the email health score work?"
> "I start at 100 points and deduct 15 for every error finding (like missing SPF) and 8 for every warning (like DMARC policy set to 'none'). The final score maps to a letter grade: A+ (95+), A (85+), B (70+), C (55+), D (40+), F (below 40)."

#### 🏗️ "Why no React/Angular/Vue?"
> "Zero build step, zero npm dependencies, zero supply-chain vulnerability surface. The entire frontend is vanilla HTML/CSS/JS — loads instantly, no webpack, no node_modules. Modern ES6 `fetch` + template literals handle everything cleanly."

---

## 🎯 Killer Answers for Common Questions

### Q: "What problem does this solve?"
> DNS misconfigurations cause website downtime, email loss, and security vulnerabilities. My tool automates what normally takes a skilled engineer 20+ minutes of manual `dig` commands into a 2-second automated diagnostic with actionable findings.

### Q: "What is SPF / DMARC / DKIM?" (They WILL ask this)
> - **SPF** (Sender Policy Framework) — a TXT record listing which IP addresses are authorized to send email for your domain. Prevents random servers from impersonating you.
> - **DMARC** (Domain-based Message Authentication, Reporting & Conformance) — tells receiving servers what to do when SPF or DKIM checks fail: `none` (monitor), `quarantine` (spam folder), or `reject` (block).
> - **DKIM** (DomainKeys Identified Mail) — uses public-key cryptography. The sending server signs each email with a private key, and the receiving server verifies it using a public key published in DNS.

### Q: "Why did you use FastAPI instead of Flask/Django?"
> FastAPI has native `async/await` support, which I need for concurrent DNS queries. Flask is synchronous by default. Django is an ORM-heavy full-stack framework — overkill for an API-focused tool. FastAPI also gives me automatic Pydantic validation and OpenAPI docs for free.

### Q: "What is asyncio.gather and why does it matter?"
> `asyncio.gather` takes multiple coroutines (async functions) and runs them concurrently on the event loop. Instead of waiting for each DNS query to finish before starting the next one, all 7 queries run at the same time. The total time is the time of the **single slowest query**, not the sum of all queries.

### Q: "What is the RFC 7208 10-lookup limit for SPF?"
> RFC 7208 says that evaluating an SPF record must not require more than 10 DNS lookups (for mechanisms like `include`, `a`, `mx`, `ptr`, `exists`, `redirect`). If a domain exceeds this, receiving servers may return a `PermError` and reject the email. My tool counts the exact lookups recursively and flags domains that are over or approaching the limit.

### Q: "How does the report download work?"
> When you click Download Report, the browser requests `GET /api/report/{domain}`. The backend re-runs the full analysis, passes all data to a Jinja2 HTML template that has **all CSS styles embedded inline** — no external files needed. The response has a `Content-Disposition: attachment` header so the browser downloads it as a `.html` file. You can open it offline, email it, share it — it's fully self-contained.

### Q: "How do you handle errors — what if a domain doesn't exist?"
> At every layer: (1) Pydantic validates the domain format with a regex before any network call. (2) The DNS resolver catches `NXDOMAIN`, `NoAnswer`, `Timeout` exceptions and returns structured `{"status": "not_found"}` instead of crashing. (3) The API returns clean 400/500 JSON errors. The frontend shows a red error banner — no silent failures.

### Q: "What RFC standards does your tool check?"
> - **RFC 1034 / 1035** — DNS base specification (CNAME conflicts, NS requirements)
> - **RFC 1912 / 2182** — SOA sanity (refresh > retry, expire ≥ 2 days)
> - **RFC 5321** — MX record existence and reachability for email delivery
> - **RFC 7208** — SPF (Sender Policy Framework) syntax, 10-lookup limit
> - **RFC 7489** — DMARC (Domain-based Message Authentication)
> - **RFC 6376** — DKIM (DomainKeys Identified Mail)

### Q: "What would you add in v3?"
> 1. **DNSSEC verification** — validate the cryptographic chain of trust (DS, DNSKEY, RRSIG)
> 2. **Subdomain takeover detection** — check if CNAMEs point to unclaimed cloud resources
> 3. **Scan history with PostgreSQL** — track DNS changes over time, detect drift
> 4. **Webhook alerts** — Slack/Discord notifications when a domain's DNS health degrades
> 5. **PDF export** — alongside the current HTML report
> 6. **Bulk domain scanning** — analyze multiple domains in one go (e.g., for IT teams)

---

## 🔥 Pro Tips to Impress

### 1. Show the API directly
Open a new terminal and run:
```bash
curl -s -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain":"google.com"}' | python3 -m json.tool | head -50
```
> "The API is fully RESTful — you can integrate it with any tool, script, or CI/CD pipeline."

### 2. Show input validation
Type a bad domain like `!!!invalid` — show the clean 400 error message.
> "Pydantic validates every input against an RFC-compliant regex before any DNS query is made."

### 3. Show URL extraction
Paste `https://www.google.com/search?q=dns+analyzer` in the input box.
> "The frontend automatically extracts the hostname from any URL format — users don't need to manually clean their input."

### 4. Compare with the raw approach
```bash
dig google.com A
dig google.com AAAA
dig google.com MX
dig google.com NS
dig google.com TXT
dig google.com CNAME
dig google.com SOA
dig _dmarc.google.com TXT
dig google._domainkey.google.com TXT
```
> "This takes 9 commands and gives raw output that requires expert interpretation. My tool does all of this in one click, adds automated analysis, and presents it in a beautiful dashboard."

### 5. Talk about the email health score
> "I built a scoring engine that quantifies email security posture into a single number. This is similar to what enterprise tools like Valimail, MXToolbox, and dmarcian charge for — I built an open-source version."

---

## 📁 Project File Summary

| File | Purpose | Lines |
|------|---------|-------|
| `app/main.py` | FastAPI routes, email auth integration | ~170 |
| `app/resolver.py` | Async concurrent DNS resolution | ~120 |
| `app/analyzer.py` | 9 RFC-based diagnostic rules | ~180 |
| `app/spf.py` | SPF parsing, lookup counting, flattening | ~495 |
| `app/email_auth.py` | DMARC/DKIM analysis, health scoring | ~333 |
| `app/models.py` | Pydantic schemas (request/response) | ~67 |
| `app/report.py` | Jinja2 self-contained HTML report | ~335 |
| `static/index.html` | Dashboard UI with email auth sections | ~160 |
| `static/style.css` | Dark theme design system | ~630 |
| `static/app.js` | Frontend logic, rendering, animations | ~497 |
| `setup.sh` | Automated environment setup | ~60 |
| `start.sh` | Server launcher with port validation | ~60 |
| `Dockerfile` | Container image build | ~18 |

**Total:** ~3,100+ lines of handwritten code

---

## 🎤 Closing Statement (Use This to End)

> *"DNS Analyzer v2 goes beyond basic DNS lookups. It's a complete domain health platform that combines infrastructure diagnostics with email security analysis. It uses concurrent async I/O for performance, follows RFC standards for accuracy, and presents everything in an accessible, downloadable format. The entire stack — backend, frontend, report engine — is built from scratch with zero framework bloat. Thank you."*

---

## 🚀 Quick Start Commands

```bash
# Navigate to the project
cd ~/Desktop/dns-analyzer

# Install everything
bash setup.sh

# Start the server
bash start.sh

# Open → http://127.0.0.1:8000
```
