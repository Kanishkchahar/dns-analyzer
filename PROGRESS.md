# Project status

This snapshot reflects the current 2.2.0 codebase and its reviewed behavior. Run `./venv/bin/pytest -q` for the current test count; counts are intentionally not treated as a release promise.

## Implemented

- Browser dashboard, FastAPI routes, shared Python scan pipeline, and CLI.
- DNS, email-authentication, selected DNSSEC, TLS/web, CT inventory, takeover, and authoritative-posture checks.
- Per-scan work budgets, bounded network diagnostics, coverage states, finding codes, remediation drafts, and JSON/SARIF/offline report exports.
- Inconclusive handling for failed lookups, provisional score reporting, and browser-local scan comparisons.

## Known gaps

- The DNSSEC chain validator is opt-in and does not fully validate authenticated denial proofs.
- Scan history, caches, and rate limits are local to the browser or server process. There is no built-in scheduled monitoring, alert delivery, or account system.
- The API has no bulk full-analysis endpoint, and the package does not expose a separately documented SDK/config-driven audit interface.
- RDAP expiry and dangling-nameserver registration checks are not implemented.

See [design decisions](DECISIONS.md), the [scan guide](docs/scan.md), and [deployment notes](docs/DEPLOYMENT.md) for current behavior and limits.
