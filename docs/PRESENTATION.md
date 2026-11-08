# DNS Analyzer presentation guide

Use this guide for a short product demo or technical walkthrough. Live scan results vary; avoid promising a particular grade or provider response.

## Short introduction

> DNS Analyzer brings DNS, email authentication, selected DNSSEC, TLS, and web checks into one dashboard. It reports what completed, what could not be verified, and provides remediation drafts for review. It is a diagnostic aid, not a penetration test or proof that a domain is secure.

## Two-minute demo

1. Start the app with `bash run.sh` and open <http://127.0.0.1:8000>.
2. Scan a domain such as `example.com`; show the grade, factor breakdown, and scan coverage.
3. Open findings and explain the difference between an error, a warning, an informational note, and an inconclusive check.
4. Review DNS/email results and a remediation draft. Emphasize that suggestions are not published automatically.
5. Show JSON or SARIF output from the CLI, or download the standalone HTML report.

Optional: run a bounded common-path check from Network & Scope. Explain that it checks a fixed set of paths and does not crawl directories. Active port checks are a separate opt-in feature.

## What the dashboard summarizes

The overall score uses seven configured factors:

| Factor | Weight |
|---|---:|
| DNS infrastructure | 20 |
| Email authentication | 25 |
| DNSSEC | 20 |
| Takeover evidence | 15 |
| TLS and web | 10 |
| Mail transport | 5 |
| DNS posture | 5 |

Not-applicable factors and factors with no completed checks are excluded before the remaining weights are normalized. Unknown checks inside a partly observed factor receive neutral credit and remain labeled inconclusive. If more than 30% of total weight is excluded, the grade is marked incomplete. Confirmed AXFR exposure caps the score at 54; confirmed takeover evidence or bogus DNSSEC caps it at 39. The score is rule-based, not a probability of compromise.

Address resolution is scored once: either A or AAAA records are sufficient. This does not test whether the service is reachable over both IP families.

## Architecture at a glance

```text
Browser dashboard ──┐
                    ├── FastAPI routes ── shared scan pipeline
Python CLI ─────────┘                         │
                                              ├── DNS record collection
                                              ├── SPF / DMARC / DKIM / mail transport
                                              ├── DNSSEC, takeover, and DNS posture
                                              ├── TLS, HTTP headers, and CT inventory
                                              └── findings, scores, coverage, and reports
```

`app/main.py` coordinates the shared scan pipeline used by the API and CLI. Individual checks live in focused modules under `app/`. DNS and HTTP work is bounded by timeouts, concurrency limits, and per-scan budgets. The static dashboard uses HTML, CSS, and JavaScript; Jinja2 generates offline reports.

## Check groups

- **DNS infrastructure:** A/AAAA, MX, NS, TXT, CNAME, SOA, and CAA; zone-apex discovery; selected resolution, redundancy, CNAME, SOA, TTL, and CAA checks.
- **Email authentication:** SPF syntax and DNS lookup expansion, DMARC policy, common and custom DKIM selectors, MTA-STS, TLS-RPT, and BIMI.
- **DNSSEC and authoritative posture:** default DS-to-DNSKEY comparison; optional chain evidence; count-only AXFR detection; wildcard DNS and direct nameserver consistency.
- **Web and inventory:** certificate validity and negotiated TLS, HTTPS behavior and selected headers, passive Certificate Transparency inventory, and takeover fingerprints.
- **Optional diagnostics:** bounded common paths, DNS-only target lists, and authorized TCP port checks.

See the [scan guide](scan.md) for details, statuses, and limitations.

## Important limitations to explain

- Default DNSSEC checking does not validate the full signature chain to the root. The opt-in chain validator is informational, and authenticated denial proofs are incomplete.
- Takeover fingerprints are heuristic. Shipped entries are unverified; a match is a candidate unless a future catalog entry has a recent verification date and the evidence requirements are met. Even then, claimability is not proven.
- A CT inventory is not a complete asset inventory. CT results can be missing, stale, or unavailable.
- A published SPF, DKIM, DMARC, or mail-transport record does not prove that real mail is correctly configured or delivered.
- TLS and header checks inspect bounded observations; they do not test every protocol option or application behavior.
- Scan history is browser-local. The app has no built-in server-side scheduler, accounts, or alert delivery.
- Cache and rate-limit state is process-local. Multi-worker deployments need a shared proxy or store for consistent behavior.

## Technical questions

### Why use asynchronous checks?

DNS and HTTP checks spend much of their time waiting on network responses. Async execution lets independent checks overlap. Timeouts, semaphores, and work budgets bound the effect of slow or unusually large scans.

### What does “inconclusive” mean?

The scanner did not get enough evidence to determine whether a condition is present. A timeout or exhausted budget is not treated as proof that a record is absent or a check passed.

### How should users interpret a missing SPF record?

It may be intentional, especially on a hostname that does not send mail. The tool provides a sender-confirmation checklist instead of inventing an SPF policy from MX records alone.

### What does a takeover candidate establish?

It shows a dangling-looking CNAME or matching fingerprint worth reviewing. It does not establish that a third party can claim the target resource.

### Is DNSSEC fully validated?

No. By default the scanner compares supported DS and DNSKEY data. Optional chain validation reports additional evidence but does not affect scoring; denial-proof validation is incomplete.

### Does a warning mean the domain is exploitable?

No. Findings identify configuration signals and should be checked against the domain's intended use, evidence, and provider behavior. Remediation entries are drafts for human review.

## Useful commands

```bash
bash run.sh
bash run.sh --test
./venv/bin/dns-analyzer example.com
./venv/bin/dns-analyzer example.com --json
./venv/bin/dns-analyzer example.com --sarif
```

For endpoint examples, see the [API guide](API.md). For deployment settings and outbound requests, see [deployment and privacy](DEPLOYMENT.md).
