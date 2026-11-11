# Deployment and privacy

## Safe defaults

- `bash run.sh` binds to `127.0.0.1:8000`. Use `DNS_ANALYZER_HOST` to change the bind address. The Docker image listens on `0.0.0.0` inside its network namespace; use the published port mapping to control host exposure.
- Public deployments should sit behind an authenticated, rate-limited reverse proxy. The application does not provide user accounts or authentication for general scan endpoints.
- Active TCP port scanning is disabled by default. Enable it only when you have an authorization policy and approved target scope.
- The DNS, CT, and HTTP checks make outbound requests. Parent-child delegation checks send bounded UDP/TCP DNS queries to public parent authoritative nameserver addresses discovered through DNS. Use the tool only for domains and hosts you are authorized to assess.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DNS_ANALYZER_HOST` | `127.0.0.1` | Host interface used by `run.sh`. |
| `ENABLE_ACTIVE_PORT_SCAN` | auto (on in local trust mode) | Master switch for active TCP port checks, including the extended 100-port list. Unset defaults to enabled when no `DNS_ANALYZER_API_KEYS` are configured, and disabled otherwise. |
| `PORT_SCAN_API_KEY` | unset | Bearer token required by the port-scan policy. |
| `PORT_SCAN_ALLOWED_DOMAINS` | unset | Comma-separated approved target domains. |
| `ENABLE_WIDE_DIRECTORY_SCAN` | auto (on in local trust mode) | Enable the fixed 64-path directory list. Unset defaults to enabled when no `DNS_ANALYZER_API_KEYS` are configured, and disabled otherwise. |
| `WIDE_PATH_SCAN_API_KEY` | unset | Optional bearer token required for wide directory scans. |
| `WIDE_PATH_SCAN_ALLOWED_DOMAINS` | unset | Comma-separated approved domains for wide directory scans. |
| `CERTSPOTTER_API_KEY` | unset | Optional SSLMate Cert Spotter API bearer token for higher CT query availability. |
| `TRUST_REVERSE_PROXY` | `false` | Read `X-Forwarded-For` for rate limiting. Enable only when direct access to the app is blocked and the proxy chain is trusted. |
| `TRUSTED_PROXY_COUNT` | `1` | With proxy trust enabled, select this many valid addresses from the right of `X-Forwarded-For`. Must match the trusted proxy hops represented in the header; insufficient valid entries fall back to the socket peer. |
| `DNS_ANALYZER_API_KEYS` | unset | Optional comma-separated bearer keys required by scan, report, and `/api/network/*` endpoints. Enter the key under the dashboard's “API access” control; it is held for the current browser tab only. |
| `DNS_ANALYZER_RATE_LIMIT_PER_MIN` | `60` | Per-client rate limit for ordinary API requests. Loopback requests retain a minimum allowance of 120 per minute. |
| `DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN` | `10` | Per-client limit for full scans, reports, batch scans, and network diagnostics. |
| `DNS_ANALYZER_TARGET_COOLDOWN_SECONDS` | `10` | Minimum interval between repeated checks of the same target and check type, regardless of client. |
| `DNS_ANALYZER_BLOCKED_TARGETS` | unset | Comma-separated local hostnames or addresses that must not be scanned. The server's current hostname and FQDN are blocked automatically. |
| `DNS_ANALYZER_DOCUMENTATION_URL` | placeholder URL | Contact/documentation link placed in the scanner User-Agent. |
| `ENABLE_DNSSEC_CHAIN_VALIDATION` | `false` | Enable additional informational DNSSEC chain evidence. It does not affect the score. |

For active port scans, the dashboard sends `PORT_SCAN_API_KEY` in `X-Port-Scan-Token`; the older request-body `auth_token` field remains temporarily supported. Extended path scans use `X-Wide-Path-Token`. When global API-key protection is enabled, its key is sent separately in `Authorization: Bearer …`.

### Enabling optional network scans

These checks stay disabled until the server operator enables them and defines an authorization policy. `nmap` is an operating-system executable, not a Python package: the Docker runtime installs it already. On a Debian/Ubuntu host running `bash run.sh`, install it with `sudo apt-get install nmap` if you want Nmap service/version detection; the basic TCP mode does not require Nmap.

Set the scan-policy variables directly in the shell before starting the server. `bash run.sh` uses inherited variables, and `bash run.sh --docker` forwards the scan-policy variables into the container. No environment file is required.

For a local server, set the feature switch and restrict it to domains you are authorized to assess before starting the app:

```sh
ENABLE_ACTIVE_PORT_SCAN=true \
PORT_SCAN_ALLOWED_DOMAINS=your-domain.example \
PORT_SCAN_API_KEY='choose-a-long-secret' \
bash run.sh
```

In the dashboard, enter the same port key and confirm authorization. For Docker, pass the same settings when starting the container:

```sh
docker run --rm -p 127.0.0.1:8000:8000 \
  -e ENABLE_ACTIVE_PORT_SCAN=true \
  -e PORT_SCAN_ALLOWED_DOMAINS=your-domain.example \
  -e PORT_SCAN_API_KEY='choose-a-long-secret' \
  dns-analyzer
```

The 64-path option is separate. To enable it, set `ENABLE_WIDE_DIRECTORY_SCAN=true`, configure `WIDE_PATH_SCAN_ALLOWED_DOMAINS` and/or `WIDE_PATH_SCAN_API_KEY`, restart the server, and provide the configured key in the extended-scan field. Leave the extended-list checkbox off to use the standard seven-path check without wide-scan authorization. Never use `*` or a domain you do not control in the allowlist.

The dashboard reads `GET /api/network/capabilities` on load, so the Network Scope panel shows whether each optional check is enabled, disabled, or waiting for a key/allowlist, and disables controls the server would refuse. This reporting is informational only; every probe is still re-authorized server-side on each request. There is deliberately no UI toggle that overrides the policy — enabling a feature means changing the server environment and restarting.

### Public deployment threat model

DNS Analyzer makes DNS and bounded HTTP or TCP requests on behalf of its caller. A public instance can therefore be abused as a scanning proxy. Keep it behind a trusted reverse proxy, enable `DNS_ANALYZER_API_KEYS`, set conservative rate and target cooldown limits, and configure `DNS_ANALYZER_BLOCKED_TARGETS` with any public aliases or addresses that route back to the deployment. Special-use suffixes such as `.local`, `.internal`, `.onion`, and `.localhost` are rejected. Optional active network checks still require their own explicit authorization controls.

For a single Nginx proxy, set `TRUST_REVERSE_PROXY=true` and `TRUSTED_PROXY_COUNT=1`, and use `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`. If Cloudflare is in front of Nginx and both hops are represented in the header, set the count to `2`. Restrict network access so clients cannot reach the application directly; otherwise they can forge this header.

## Data, logs, and retention

- Scan history is stored in the current browser profile, not on the server.
- Scan, path, DKIM, badge caches and rate limits are held in process memory. They are cleared on restart and are not shared across workers. Use one worker or add a shared store/proxy for consistent behavior.
- Python and Uvicorn logs go to the process output by default. The host or container runtime controls log collection and retention. Logs can include client IPs, requested paths/domains, and diagnostic exception details. API errors are sanitized, but server logs may be more detailed.
- The application does not configure retention at external services.

## Outbound requests

- DNS questions go to the recursive resolvers configured on the application host.
- Passive subdomain discovery sends the queried domain to `crt.sh` and SSLMate Cert Spotter. RDAP checks query IANA's bootstrap data and the responsible registry; RPKI checks query RIPEstat. Nameserver ASN diversity checks send IP-derived TXT names through the configured recursive resolver to Team Cymru's `origin.asn.cymru.com` and `origin6.asn.cymru.com` services. MX reputation checks send reversed public MX IPv4 addresses through that resolver to `zen.spamhaus.org`, `b.barracudacentral.org`, and `bl.spamcop.net`; these providers can observe the queried IPs.
- TLS, web-header, takeover, path, Nmap, SMTP STARTTLS, and MTA-STS checks make bounded requests or connections to public hosts associated with the scan.
- Requests have timeouts and size/work limits. Target HTTP connections use validated public IPs; network checks block non-public targets. Redirect handling is bounded or disabled according to the check.

## Work limits

The full scan has a shared budget of 500 DNS queries and 37 outbound HTTP requests, with reserved module shares. Unused module shares are not borrowed. Standalone common-path checks have a 20-request HTTP budget for seven standard paths, same-host redirects, and up to three advertised sitemap paths. The optional 64-path mode has a 160-request cap. Other standalone network diagnostics use a separate, bounded network-scan budget. Exhausted checks are reported as incomplete or inconclusive.

The scan concurrency limit is eight requests per process, with a bounded queue wait and a 60-second full-scan timeout. The API rate limiter allows 60 requests per minute per client IP, or 120 for loopback; it is also per process. Full scans allow up to 37 outbound HTTP requests, including RDAP, RPKI and plugin checks.

`uv.lock` is the resolver lockfile and `requirements.lock.txt` is its production-only, hash-pinned pip export. After changing `pyproject.toml` dependencies, regenerate both with `uv lock` and `uv export --format requirements-txt --no-dev --no-emit-project --output-file requirements.lock.txt`.

## Docker

The default Docker build runs the test suite in an isolated test stage before assembling the runtime image. The runtime image does not contain pytest or development tools. To run the test stage directly, use `docker build --target test .`. The image includes Nmap for optional service/version identification. Build and run with:

```bash
docker build -t dns-analyzer .
docker run --rm -p 8000:8000 dns-analyzer
```

The container publishes port 8000. Follow the same proxy and authorization guidance before exposing it outside a trusted local network.
