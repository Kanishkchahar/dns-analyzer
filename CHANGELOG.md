# Changelog

## Unreleased

- Report optional scan readiness through `GET /api/network/capabilities` and show it in the Network Scope panel, which now disables controls the server would refuse and explains the environment variables that enable them.
- Add a fixed 100-port extended `connect` profile (`wide: true`) for authorized targets when Nmap is unavailable; the authorization policy and per-scan caps are unchanged.
- Enable active and wide scans automatically in local trust mode (no `DNS_ANALYZER_API_KEYS` configured) so a default local run works without extra environment variables or tokens.

- Honor `TRUST_REVERSE_PROXY` with configurable `TRUSTED_PROXY_COUNT`; malformed forwarded entries are ignored and insufficient chains fall back to the socket peer.
- Add a Docker test stage that gates the runtime build, and split development tools from runtime requirements.
- Add Python 3.11–3.13 CI, a core Ruff check, advisory pip-audit and Bandit jobs, and weekly Dependabot updates.
- Add the MIT license.
- Refresh README and presentation limitations, document the CLI and SARIF workflow, and schema-check the documented API response excerpt.
- Replace private HTTPX pool-field access with an explicit pinned httpcore backend and caller-built TLS context; relax supported dependency ranges and exercise lowest/latest resolution in CI.
- Add optional bearer-key protection, configurable ordinary and expensive API limits, per-target scan cooldowns, and validation blocks for private suffixes and configured server aliases.
- Give standalone common-path checks enough bounded HTTP work for all seven paths and same-host redirects; retain a separate 160-request cap for wide mode.
- Raise the minimum pytest/pytest-asyncio versions to their compatible range after the lowest-resolution run exposed an old plugin collection failure.
- Add bounded RDAP expiry, TLS protocol, RPKI, TLSA, SMTP STARTTLS, Cert Spotter discovery, multi-domain comparison, and plugin checks; document their evidence limits.
- Let the dashboard supply optional API credentials per tab and keep global, extended-path, and port-scan tokens in separate request headers.
- Cache local hostname and FQDN discovery once per process when validating blocked scan targets.
- Add budgeted Team Cymru ASN observations for authoritative nameserver addresses; only complete shared-origin evidence produces a warning, which is excluded from grading.
- Check up to three MX hosts and two public IPv4 addresses per host against Spamhaus ZEN, Barracuda BRBL, and SpamCop using a dedicated DNS budget; provider access-limit responses remain inconclusive.
- Compare observed HTTPS and SMTP leaf certificates/SPKIs with supported DANE-EE TLSA associations using pinned, budgeted probes; report matches without claiming DNSSEC-authenticated DANE validation.
- Emit an additive Root-to-zone DNSSEC graph payload and render the chain in the dashboard when opt-in chain validation is enabled; denial proofs remain unvalidated.
- Compare parent NS referrals and in-bailiwick glue with direct child-authority responses; mismatches are reported only when two parent authorities agree and child answers are authoritative.
- Resolve NS and MX targets over both IPv4 and IPv6; add per-target address-family/status evidence and report failed family lookups as inconclusive.
- Add a stop control for analysis and bounded scope scans; detect client disconnects, cancel server scan tasks, and clean up active TCP/Nmap probes. Put scope tools before passive inventory with a live scan status.
- Clarify optional network scan setup: report required server policy variables, document direct local/Docker environment configuration, and verify Nmap is present in the runtime image.
- Expand optional Nmap service identification and bounded wide directory discovery.
- Score address resolution once: an A or AAAA record is enough, so IPv4-only and IPv6-only domains are not penalized for lacking the other family.
- Treat failed or timed-out DNS checks as inconclusive instead of reporting records as missing; the SPF card and email grade also show when TXT lookup did not complete.
- Display inconclusive findings across the dashboard, CLI, and HTML report, and add SARIF 2.1.0 CLI output for CI integrations.
- Require provider fingerprints to have a verification date within the last year before they can produce confirmed takeover results. Stale, undated, and unverified fingerprints remain candidates.

## 2.2.0

- Repair the live DNSSEC delegation check: uncomparable DS data is inconclusive and DNSKEY without parent DS is incomplete chain. The opt-in chain validator reports `chain_status` informationally; the legacy status remains compatible and controls scoring.
- Standardize unavailable DNSSEC outcomes on `inconclusive`; opt-in chain results do not change score, grade, or caps.

- Security hardening: maintain exact `httpx==0.28.1` and `httpcore==1.0.9` pins; sitemap XML parsing uses `defusedxml` and rejects entity payloads.
- Reserve the 500-DNS-query / 25-HTTP-fetch budget by module for full scans; standalone network routes receive per-request shares. Exhausted checks are reported as inconclusive.
- Add a configurable scanner User-Agent (`DNS_ANALYZER_DOCUMENTATION_URL`, defaulting to the editable placeholder URL).
- Use generic user-facing failure reasons while retaining diagnostic detail in server logs.
- Keep the port-scan JSON `auth_token` field temporarily with a deprecation warning; `Authorization: Bearer` is preferred. Remove the body field in version 2.3.0.
- Document process/browser storage, logging, outbound DNS/CT/target requests, and their unconfigured retention limits.

- Exclude factors that are not applicable or have no completed checks, then normalize the remaining factor weights to 100.
- Mark the grade provisional when excluded factors exceed 30% of total weight; expose excluded factors and factor completion in the score breakdown.
- Document exact takeover-state deductions. Candidates deduct points but do not activate the confirmed-takeover cap.
- Unknown finding codes now log an error and use the generic code in production. Tests remain strict so module findings with uncatalogued codes fail the test suite.
- **Grades and `--min-grade` results may differ from earlier versions** because score normalization and incomplete-grade reporting changed.
