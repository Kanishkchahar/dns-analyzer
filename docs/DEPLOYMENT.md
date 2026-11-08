# Deployment and privacy

## Safe defaults

- `bash run.sh` binds to `127.0.0.1:8000`. Use `DNS_ANALYZER_HOST` to change the bind address. The Docker image listens on `0.0.0.0` inside its network namespace; use the published port mapping to control host exposure.
- Public deployments should sit behind an authenticated, rate-limited reverse proxy. The application does not provide user accounts or authentication for general scan endpoints.
- Active TCP port scanning is disabled by default. Enable it only when you have an authorization policy and approved target scope.
- The DNS, CT, and HTTP checks make outbound requests. Use the tool only for domains and hosts you are authorized to assess.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DNS_ANALYZER_HOST` | `127.0.0.1` | Host interface used by `run.sh`. |
| `ENABLE_ACTIVE_PORT_SCAN` | `false` | Master switch for active TCP port checks. |
| `PORT_SCAN_API_KEY` | unset | Bearer token required by the port-scan policy. |
| `PORT_SCAN_ALLOWED_DOMAINS` | unset | Comma-separated approved target domains. |
| `TRUST_REVERSE_PROXY` | `false` | Use the rightmost valid `X-Forwarded-For` address for rate limiting. Enable only behind a proxy that appends the observed client address or replaces incoming values. When disabled behind a proxy, requests share the proxy's rate-limit bucket. |
| `DNS_ANALYZER_DOCUMENTATION_URL` | placeholder URL | Contact/documentation link placed in the scanner User-Agent. |
| `ENABLE_DNSSEC_CHAIN_VALIDATION` | `false` | Enable additional informational DNSSEC chain evidence. It does not affect the score. |

The port-scan API accepts the token in the `Authorization` header. The request-body token field is deprecated.

## Data, logs, and retention

- Scan history is stored in the current browser profile, not on the server.
- Scan, path, DKIM, badge caches and rate limits are held in process memory. They are cleared on restart and are not shared across workers. Use one worker or add a shared store/proxy for consistent behavior.
- Python and Uvicorn logs go to the process output by default. The host or container runtime controls log collection and retention. Logs can include client IPs, requested paths/domains, and diagnostic exception details. API errors are sanitized, but server logs may be more detailed.
- The application does not configure retention at external services.

## Outbound requests

- DNS questions go to the recursive resolvers configured on the application host.
- Passive subdomain discovery sends the queried domain to `crt.sh`.
- TLS, web-header, takeover, path, and MTA-STS checks make bounded requests to public hosts associated with the scan.
- Requests have timeouts and size/work limits. Target HTTP connections use validated public IPs; network checks block non-public targets. Redirect handling is bounded or disabled according to the check.

## Work limits

The full scan has a shared budget of 500 DNS queries and 25 outbound HTTP requests, with reserved module shares. Unused module shares are not borrowed. Standalone network diagnostics use a separate, bounded network-scan budget. Exhausted checks are reported as incomplete or inconclusive.

The scan concurrency limit is eight requests per process, with a bounded queue wait and a 60-second full-scan timeout. The API rate limiter allows 60 requests per minute per client IP, or 120 for loopback; it is also per process.

## Docker

The Dockerfile includes a test stage before the production image. Build and run with:

```bash
docker build -t dns-analyzer .
docker run --rm -p 8000:8000 dns-analyzer
```

The container publishes port 8000. Follow the same proxy and authorization guidance before exposing it outside a trusted local network.
