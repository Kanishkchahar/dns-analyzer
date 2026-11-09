# API guide

The API is served by the same FastAPI app as the dashboard. JSON routes accept and return UTF-8 JSON unless noted. Domain inputs accept a hostname or a full HTTP(S) URL; the app extracts and validates the hostname.

## Main scan

`POST /api/analyze`

```json
{"domain":"example.com","force_refresh":false}
```

`force_refresh` bypasses the short in-process scan cache. The response includes DNS records, findings and stable codes, scan coverage, scores, email and security checks, subdomains, and remediation drafts. A successful HTTP response can still contain partial or inconclusive checks; inspect `coverage`, `findings`, and module statuses.

NS and MX record entries include the compatible `resolves` boolean plus additive `resolution_status` (`resolved`, `unresolved`, or `inconclusive`) and `address_families` (`A`, `AAAA`, or both). IPv6-only hosts count as resolved. If either family lookup fails and neither returns an address, the result is inconclusive rather than an absent-host finding.

`dns_posture.nameserver_asn_diversity` reports Team Cymru origin-AS observations for public nameserver addresses. It emits `DNS-NS-ASN-001` only when all address lookups for at least two nameservers complete and return the same ASN. The warning is informational and does not affect the grade; lookup failures remain inconclusive.

`dns_posture.parent_child_delegation` compares NS records from two parent authorities with direct, authoritative child answers. It reports `DNS-NS-DELEGATION-002` for a confirmed set mismatch, `DNS-NS-DELEGATION-003` for missing in-bailiwick glue, `DNS-NS-DELEGATION-004` for a direct lame response, and `DNS-NS-DELEGATION-005` if parent authorities disagree on glue. Fewer than two consistent parent responses or incomplete child answers remain inconclusive.

When chain validation is enabled, `security.dnssec.chain_graph` contains graph `nodes` and `edges` for root trust anchors, zone delegations, DS records, DNSKEYs, and available RRSIG validity windows. Graph status reflects the opt-in chain validator; it does not include authenticated NSEC/NSEC3 denial proofs.

`extensions.extended_security.dane_tlsa` reports TLSA DNS records and compares supported DANE-EE certificate/SPKI associations against pinned observations for the HTTPS host and up to three MX hosts. It reports `MAIL-DANE-001` for a match and `MAIL-DANE-002` for a supported mismatch. DNSSEC authenticity and DANE-TA/PKIX chain validation are not established, so results are observations rather than complete DANE validation; failures remain inconclusive.

`extensions.extended_security.dnsbl` checks up to three MX hosts, at most two public IPv4 addresses each, against Spamhaus ZEN, Barracuda BRBL, and SpamCop. It reports `MAIL-DNSBL-001` only for recognized positive response codes; Spamhaus PBL codes are warnings, and provider limits or unknown responses are inconclusive. These DNS queries disclose the checked MX IPs to the listed providers via the configured recursive resolver.

This trimmed response excerpt shows the backward-compatible response shape; real scans populate the optional fields according to available evidence. The checked-in [response example](examples/analyze-response.json) is validated against `AnalyzeResponse` in the test suite.

```json
{"domain":"example.com","scan_timestamp":"2026-11-08T00:00:00Z","records":{},"findings":[],"summary":{"errors":0,"warnings":0,"info":0,"inconclusive":0},"domain_score":null,"extensions":{}}
```

### Multi-domain comparison

`POST /api/analyze/batch` accepts 2–8 domains and returns per-domain scan results or per-domain errors. Each domain consumes one unit from the IP request budget. The dashboard accepts comma, semicolon, or newline-separated domains and presents score, finding counts, and the highest-priority finding for each result.

```json
{"domains":["example.com","example.org"],"force_refresh":true}
```

## Other routes

| Method and path | Request / response | Purpose |
|---|---|---|
| `POST /api/email/dkim-selectors` | `{"domain":"example.com","selectors":["selector1"]}` | Check 1–20 supplied DKIM selectors. |
| `GET /api/subdomains/{domain}` | JSON inventory | Query Certificate Transparency and resolve discovered names. |
| `GET /api/report/{domain}` | Downloadable HTML | Build an offline report, reusing a recent scan when available. |
| `GET /api/badge/{domain}` | SVG image | Return a badge only when a recent scan exists in this process; otherwise return `404`. |
| `POST /api/network/list-scan` | `{"targets":["example.com"]}` | DNS-only scope checks for up to 50 targets. |
| `POST /api/network/path-scan` | `{"targets":["example.com"]}` | Common-path checks for up to 5 targets. `wide:true` enables the fixed 64-path list for up to 2 targets, requires `confirmed:true`, and is subject to wide-scan server policy. |
| `POST /api/network/port-scan` | See below | Authorized, opt-in TCP port checks. |
| `GET /health/live` | `{"status":"alive"}` | Process liveness. |
| `GET /health/ready` | JSON readiness status | Check that dashboard assets are present. |

### Port scan request

```json
{"target":"example.com","ports":[443,8443],"confirmed":true}
```

Port checks are disabled unless the server operator enables the required policy. Configure an authorization token and/or allowed domains. The dashboard sends a port-specific token in `X-Port-Scan-Token`; the body `auth_token` field is deprecated. Global API authentication, when enabled, is sent separately in `Authorization: Bearer <token>`. Private, loopback, and other non-public targets are blocked; only scan systems you own or are authorized to assess.

Set `scanner` to `nmap` to request top-100 TCP service/version identification (requires the Nmap binary), or use `connect` for the eight common TCP ports. Nmap scans use TCP connect mode and light version probes; vulnerability scripts and UDP scans are not enabled.

Wide path requests use `ENABLE_WIDE_DIRECTORY_SCAN`, `WIDE_PATH_SCAN_ALLOWED_DOMAINS`, and/or `WIDE_PATH_SCAN_API_KEY`. The dashboard sends a configured extended-scan token in `X-Wide-Path-Token`. The UI confirmation alone does not override server policy.

### Response statuses and errors

Validation failures return `422`; handlers that validate path parameters may return `400`. Rate limiting returns `429`, scan queue saturation can return `503`, and timeouts can return `504`. Error bodies use a `detail` field. A DNS `no_answer` or `nxdomain` is a completed lookup; `timeout`, `no_nameservers`, `error`, and budget exhaustion mean the result is unknown. See [status interpretation](scan.md#reading-statuses-correctly).

If the dashboard aborts an analysis or scope-scan request, the API cancels its in-flight scan task when it detects the client disconnect. This includes stopping active TCP probes and terminating a running Nmap process.

## Limits

The server applies an in-process request limit of 60 requests per minute per client IP (120 for loopback), an eight-scan concurrency semaphore, scan timeouts, and per-scan DNS/HTTP budgets. These limits and caches are per process; use a shared proxy or storage layer if deploying multiple workers. See [deployment notes](DEPLOYMENT.md).
