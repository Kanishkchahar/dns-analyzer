# API guide

The API is served by the same FastAPI app as the dashboard. JSON routes accept and return UTF-8 JSON unless noted. Domain inputs accept a hostname or a full HTTP(S) URL; the app extracts and validates the hostname.

## Main scan

`POST /api/analyze`

```json
{"domain":"example.com","force_refresh":false}
```

`force_refresh` bypasses the short in-process scan cache. The response includes DNS records, findings and stable codes, scan coverage, scores, email and security checks, subdomains, and remediation drafts. A successful HTTP response can still contain partial or inconclusive checks; inspect `coverage`, `findings`, and module statuses.

## Other routes

| Method and path | Request / response | Purpose |
|---|---|---|
| `POST /api/email/dkim-selectors` | `{"domain":"example.com","selectors":["selector1"]}` | Check 1–20 supplied DKIM selectors. |
| `GET /api/subdomains/{domain}` | JSON inventory | Query Certificate Transparency and resolve discovered names. |
| `GET /api/report/{domain}` | Downloadable HTML | Build an offline report, reusing a recent scan when available. |
| `GET /api/badge/{domain}` | SVG image | Return a badge only when a recent scan exists in this process; otherwise return `404`. |
| `POST /api/network/list-scan` | `{"targets":["example.com"]}` | DNS-only scope checks for up to 50 targets. |
| `POST /api/network/path-scan` | `{"targets":["example.com"]}` | Bounded fixed-path checks for up to 5 targets. |
| `POST /api/network/port-scan` | See below | Authorized, opt-in TCP port checks. |
| `GET /health/live` | `{"status":"alive"}` | Process liveness. |
| `GET /health/ready` | JSON readiness status | Check that dashboard assets are present. |

### Port scan request

```json
{"target":"example.com","ports":[443,8443],"confirmed":true}
```

Port checks are disabled unless the server operator enables the required policy. Configure an authorization token and/or allowed domains. Send the token as `Authorization: Bearer <token>`. The body `auth_token` field is deprecated. Private, loopback, and other non-public targets are blocked; only scan systems you own or are authorized to assess.

### Response statuses and errors

Validation failures return `422`; handlers that validate path parameters may return `400`. Rate limiting returns `429`, scan queue saturation can return `503`, and timeouts can return `504`. Error bodies use a `detail` field. A DNS `no_answer` or `nxdomain` is a completed lookup; `timeout`, `no_nameservers`, `error`, and budget exhaustion mean the result is unknown. See [status interpretation](scan.md#reading-statuses-correctly).

## Limits

The server applies an in-process request limit of 60 requests per minute per client IP (120 for loopback), an eight-scan concurrency semaphore, scan timeouts, and per-scan DNS/HTTP budgets. These limits and caches are per process; use a shared proxy or storage layer if deploying multiple workers. See [deployment notes](DEPLOYMENT.md).
