# Design decisions

This file records current behavior that affects scan results or deployment. Check the linked guides for implementation details.

## Evidence and scoring

- A DNS failure is not treated as an empty answer. Failed lookups are reported as inconclusive; `no_answer` and `nxdomain` are definitive DNS responses.
- A or AAAA resolution is sufficient for the address-resolution score. A domain is not penalized solely for lacking the other address family.
- The overall grade uses documented weighted factors. Not-applicable and wholly unobserved factors are excluded; partial factors show their incomplete checks and scoring treatment.
- Default DNSSEC status is a DS-to-DNSKEY comparison. Optional chain validation remains informational until denial-proof handling and scoring rules are complete.
- Takeover evidence remains a candidate unless its fingerprint is explicitly verified, has a verification date within the last year, and meets the evidence rule. Confirmation still does not prove provider-side claimability.

## Runtime and safety

- Full scans use a shared cap of 500 DNS queries and 25 outbound HTTP requests with reserved module shares. Unused shares are not borrowed.
- Active TCP port checks are disabled by default and require explicit server policy and authorization. Non-public targets are blocked.
- Target HTTP requests use bounded timeouts and response sizes. Scans report partial results instead of treating a failed optional check as a pass.
- Browser history is local to the browser profile. Server caches and rate limits are process-local and are not a persistent monitoring system.

See [deployment and privacy](docs/DEPLOYMENT.md) for configuration and [the scan guide](docs/scan.md) for result interpretation.
