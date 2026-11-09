# Project status

This snapshot reflects the current 2.2.0 codebase and its reviewed behavior. Run `./venv/bin/pytest -q` for the current test count; counts are intentionally not treated as a release promise.

## Implemented

- Browser dashboard, FastAPI routes, shared Python scan pipeline, and CLI.
- DNS, email-authentication, selected DNSSEC, TLS/web, CT inventory, takeover, and authoritative-posture checks.
- RDAP registration-expiry warnings, bounded TLS-version observations, RIPEstat RPKI status, TLSA record discovery, and SMTP STARTTLS handshakes.
- crt.sh and Cert Spotter passive CT sources; multi-domain dashboard comparisons; built-in and entry-point scan plugins.
- Optional authorized TCP connect/Nmap service checks and a fixed, bounded directory-path scan.
- Per-scan work budgets, bounded network diagnostics, coverage states, finding codes, remediation drafts, and JSON/SARIF/offline report exports.
- Inconclusive handling for failed lookups, provisional score reporting, and browser-local scan comparisons.

## Known gaps

- Default DNSSEC checks compare DS and DNSKEY data. The opt-in chain validator remains informational and does not validate authenticated denial proofs.
- TLS probing samples a bounded set of protocol versions; it is not a complete cipher-suite or vulnerability audit. TLSA records are reported without DNSSEC-chain or certificate-association validation.
- RPKI reports observed RIPEstat route status at scan time; it does not validate the domain's complete network path.
- Takeover detection is limited to CNAME fingerprints and bounded NS/MX dangling candidates. Shipped provider fingerprints remain unverified, and DNS evidence does not prove claimability.
- CT discovery queries crt.sh and Cert Spotter but is not exhaustive or paginated across all certificate history.
- RDAP currently reports domain expiry when the registry publishes an expiration event; it does not report registrar locks, domain age, or dangling nameserver registration.
- Scan history, caches, and rate limits are local to the browser or server process. There is no built-in scheduled monitoring, alert delivery, or account system.
- The API has a small synchronous multi-domain comparison route, not an asynchronous bulk-job API. The package does not expose a separately documented SDK/config-driven audit interface.
- CI checks run on Python 3.11–3.13; the Docker image currently builds for its configured platform and is not published as a multi-architecture image.

See [design decisions](DECISIONS.md), the [scan guide](docs/scan.md), and [deployment notes](docs/DEPLOYMENT.md) for current behavior and limits.
