# DNS Analyzer scan guide

This guide describes the checks DNS Analyzer runs, what their results can tell you, and what they do not establish. A scan is a point-in-time observation of public DNS and network services. It is not a penetration test, a certification, or proof that a domain is secure.

## Ways to run checks

- **Full domain analysis**: enter a domain in the dashboard, call `POST /api/analyze`, or run the CLI. The API and CLI use the shared `run_full_scan` pipeline.
- **Custom DKIM selectors**: enter selector names in the Email Security panel or call `POST /api/email/dkim-selectors`. The full scan also checks its built-in selector list.
- **Passive subdomain discovery**: view the Subdomains panel or call `GET /api/subdomains/{domain}`. Full analysis includes this check.
- **DNS-only target list**: use Network & Scope or call `POST /api/network/list-scan`.
- **Common web paths**: use Network & Scope or call `POST /api/network/path-scan`.
- **Active port verification**: use Network & Scope or call `POST /api/network/port-scan`. This is disabled unless the server operator enables and authorizes it.
- **HTML report**: `GET /api/report/{domain}` returns a report built from a recent scan or runs a scan if needed.

## Full domain analysis

The dashboard's main scan runs DNS collection first, then evaluates independent email, DNSSEC, TLS, discovery, takeover, and DNS infrastructure checks. External requests have timeouts and per-scan work limits. A slow or failed optional check should be reported as incomplete; it should not be read as a successful check.

### DNS records and hostname infrastructure

The scanner queries these record types for the submitted hostname:

| Record | What it tells you |
|---|---|
| `A` | IPv4 addresses published for the hostname. It does not prove that a web service is reachable at those addresses. |
| `AAAA` | IPv6 addresses published for the hostname. It does not prove IPv6 connectivity. |
| `MX` | Mail exchangers and priorities. The scanner also checks whether the listed mail hosts resolve. No MX record can be intentional for a hostname that does not receive mail. |
| `NS` | Nameservers associated with the hostname or its authoritative zone. The scanner checks nameserver presence, redundancy, and hostname resolution. |
| `TXT` | Text records, including records used by SPF, DMARC, DKIM, BIMI, and mail-transport policies. |
| `CNAME` | Alias target for the hostname. A CNAME alongside other data at the same owner name can indicate a DNS configuration conflict. |
| `SOA` | Zone authority and timers, including serial, refresh, retry, expire, and minimum values. The scanner flags selected unusual values. |
| `CAA` | Certificate-authority issuance restrictions. The scanner reports issue/issuewild policy and may show an inherited parent policy. |

The scanner attempts to discover the authoritative zone apex by walking up the hostname labels and looking for SOA data. When the submitted name has no separate NS or SOA answer, the dashboard may show the zone's records as inherited. CAA is also checked up the parent labels when no record is found at the queried name. Apex discovery is heuristic: review the reported owner name and `inherited_from` field, especially for delegated or unusual DNS layouts.

Additional DNS findings cover whether the hostname resolves, whether nameservers and MX hosts resolve, whether there is a single nameserver, CNAME coexistence, selected SOA timer checks, TTL values, and CAA policy. These are configuration indicators; a warning is not automatically an outage or an exploit.

### SPF

SPF analysis reads SPF TXT records for the scanned hostname. It checks for missing or multiple SPF records, parses mechanisms and policy, expands DNS-lookup mechanisms, checks the RFC lookup limit, and reports risky `all` policies. A flattening preview may be generated when the scanner determines it can do so safely.

A failed TXT lookup is reported as inconclusive. It is not treated as proof that SPF is missing, and the email grade is marked incomplete.

SPF tells receiving mail systems which senders the domain authorizes. A missing SPF record can be expected for a subdomain that does not send mail. A syntactically valid policy can still omit a legitimate sender. DNS Analyzer therefore gives a sender-confirmation checklist instead of inventing a provider-specific SPF record when it cannot establish the sending infrastructure.

### DMARC

DMARC analysis looks for `_dmarc.<domain>` and, for a subdomain without its own record, may use the discovered zone apex policy. It reports the policy (`none`, `quarantine`, or `reject`), percentage, optional subdomain policy, alignment settings, and reporting destinations where present.

DMARC describes how receivers should handle messages that fail the domain's SPF/DKIM alignment policy. `p=none` is monitoring, not enforcement. A published policy does not guarantee that every receiver applies it identically or that all spoofing is prevented. Check `inherited_from` to see when the parent policy was used.

### DKIM

DKIM discovery queries a built-in list of common selectors and can additionally check up to 20 user-supplied selector names. A found public key record is evidence that a selector is published; it does not prove that outbound messages are signed with that key or that every sending service is configured correctly. No result among checked selectors does not prove DKIM is absent: providers can use private or custom selectors. The result includes the selectors checked and marks partial or failed DNS queries separately.

### DNSSEC

By default, DNSSEC checks whether DNSKEY and parent DS data are present and whether a comparable DS digest matches a DNSKEY. It can identify a missing key, a missing DS delegation, a matching delegation, a mismatch, or an inconclusive lookup.

The default check is a **DS-to-DNSKEY delegation comparison**, not complete cryptographic validation of every answer or the entire chain to the root. Setting `ENABLE_DNSSEC_CHAIN_VALIDATION=true` enables the separate chain validator and its `chain_status` evidence plus a Root-to-zone graph payload. That opt-in result is not used for scoring. Authenticated denial proofs are not fully validated, so some absence states remain inconclusive. See [deployment notes](DEPLOYMENT.md#safe-defaults).

### BIMI

BIMI checks the default selector record at `default._bimi.<domain>` and whether the observed DMARC policy meets the scanner's eligibility rule. It reports the BIMI record, logo/VMC references, and statuses such as not configured, active, ineligible, or inconclusive. A published BIMI record and a DMARC policy do not guarantee that an inbox provider will display a logo; provider rules, logo validity, and certificates also matter.

### MTA-STS and TLS-RPT

The mail transport check queries `_mta-sts.<domain>` and `_smtp._tls.<domain>` TXT records. When MTA-STS is configured, it makes a bounded HTTPS request for the policy file on `mta-sts.<domain>` and reports whether the file's basic required fields and mode are valid. TLS-RPT results show discovered reporting URIs.

These checks inspect published policy and reporting configuration. DNS Analyzer does not send email, test a real sender-to-recipient delivery, or prove that remote mail systems obey the policy.

### Certificate Transparency subdomains and takeover indicators

Passive discovery queries `crt.sh` and SSLMate Cert Spotter, retries a bounded number of times, parses and deduplicates returned names, then checks discovered names through DNS. Cert Spotter's unauthenticated access is rate-limited; configure `CERTSPOTTER_API_KEY` for higher availability. The result distinguishes a completed search with no names from partial results, timeouts, and source failures. A failed CT lookup is not evidence that no other subdomains exist. CT only lists names represented in the queried certificate data; it is not a complete inventory of an organization's assets. Its `state` distinguishes `DISCOVERY_COMPLETED`, `NO_RESULTS`, `PARTIAL_RESULTS`, `SOURCE_UNAVAILABLE`, and `TIMEOUT`.

For the scanned hostname, and for discovered names, takeover checks inspect CNAME chains against the repository's service fingerprint catalog. They may also make bounded HTTP requests to public targets when a signature requires page evidence. Results distinguish no CNAME, candidate, confirmed fingerprint, and inconclusive checks. A dangling CNAME or matching page is a lead for review, not proof that an attacker can claim the resource. The catalog is not exhaustive and can become stale. A fingerprint must be explicitly verified and dated within the last year before it can produce a confirmed result.

The scanner also reports NXDOMAIN nameserver and MX targets as unverified dangling-dependency candidates. It does not claim these targets are registrable or exploitable. The bundled provider fingerprints remain explicitly unverified until independently checked; they can only produce candidate results.

### TLS and HTTPS

The TLS/HTTPS check first resolves the hostname and blocks non-public or mixed unsafe address results. It connects to validated public addresses and reports the negotiated protocol and cipher, certificate issuer and validity dates, and whether the certificate names cover the hostname. Certificates expiring within 30 days are flagged. A certificate failure, unreachable service, and a completed handshake are different outcomes. The optional authorized Nmap mode checks the top 100 TCP ports with light service/version probes; it does not run vulnerability scripts or a UDP scan.

The HTTP checks inspect whether the HTTP endpoint redirects toward HTTPS, selected response headers (including HSTS, CSP, frame/content-type/referrer and browser-isolation policies), and security attributes on observed cookies. CSP review checks for selected common weaknesses; it is not a full policy audit. TLS performs separate bounded handshakes for TLS 1.0 through TLS 1.3 and reports weak ciphers when observed. This is not an exhaustive cipher-suite or vulnerability sweep.

## RDAP, RPKI, DANE and SMTP TLS

The full scan queries the IANA RDAP DNS bootstrap and the responsible RDAP registry for a registration-expiry event. Some registries omit expiry or restrict responses; those outcomes are reported as unavailable or inconclusive.

RPKI results come from RIPEstat's observed route prefix/origin ASN and its RPKI validation endpoint. This is routing data at scan time, not a complete routing monitor. TLSA checks query the HTTPS hostname and up to three MX hosts, then compare observed leaf certificates/SPKIs with supported DANE-EE associations. HTTPS certificate probes use the pinned public IP while preserving the hostname for SNI; SMTP probes use a pinned public MX IP and send EHLO/STARTTLS only. A match is not a complete DANE validation: DNSSEC authenticity is not established, and DANE-TA / PKIX usage chain validation remains unsupported. Unsupported usages or failed probes remain inconclusive. No mail or authentication credentials are sent.

MX reputation checks use DNS queries for up to three MX hosts and up to two public IPv4 addresses per host against Spamhaus ZEN, Barracuda BRBL, and SpamCop. A source-specific positive DNS return code is required before the scanner reports a listing. DNSBL access-limit responses, timeouts, and budget exhaustion are inconclusive; they are not treated as clean results. The DNSBL operators can observe the queried mail-server IP addresses through the configured recursive resolver.

The separate wide path mode is a fixed, non-recursive list of at most 64 same-host HTTPS paths. It is disabled by default and requires server-side policy, an approved target list and/or an API key, plus user confirmation in the dashboard. Nmap mode performs a bounded TCP connect scan of the top 100 ports with light service/version probes. It uses the configured active-scan authorization and does not run vulnerability scripts or UDP probes.

## Check plugins

Independent checks run through the `app.check_registry` plugin contract. Built-in plugins live in `app/checks/` and are discovered automatically. Installed external plugins register through the `dns_analyzer.checks` Python entry-point group. Each check receives the domain, base resolver, shared work budget, and DNS record results, then returns a data object and findings. The registry applies a per-plugin timeout and records plugin output under `AnalyzeResponse.extensions`; adding a check does not require editing `main.py`.

The scanner also sends an `OPTIONS` request and reports methods advertised in the `Allow` header. An advertised method is not proof that the method accepts a request; the scanner does not send write-method probes. It requests `/.well-known/security.txt` with a small response limit and checks for Contact and a single valid, future Expires timestamp. Redirects, unavailable responses, and inconclusive requests are not treated as valid or missing content.

### Authoritative DNS posture

Five additional checks query authoritative infrastructure directly or compare its routed network origin:

- **AXFR**: attempts a TCP zone transfer from listed nameservers. If a transfer is allowed, the finding reports the server and record count; it does not return zone contents. A refused, unavailable, unresolved, or untested server must not be interpreted as proof that all transfer paths are safe.
- **Wildcard DNS**: queries a random high-entropy label for A and AAAA records. A match suggests wildcard behavior and helps distinguish wildcard-only CT names. One random-label result is an observation, not a complete characterization of every DNS wildcard rule.
- **Nameserver consistency**: queries listed authoritative nameserver addresses directly and compares observed SOA serials, selected SOA fields, and NS sets. Incomplete direct answers are reported as partial; they may reflect reachability or query limitations.
- **Parent-child delegation and glue**: queries up to four parent authorities directly, requires two agreeing parent referrals, and compares their NS set with direct authoritative child answers. It reports missing glue only for in-bailiwick nameservers; out-of-bailiwick glue is not required. A query or budget failure, or disagreement among authorities, is inconclusive.
- **Nameserver network diversity**: resolves public A/AAAA addresses for each listed nameserver and queries Team Cymru's origin service through the configured recursive resolver. It reports a warning only when complete observations for at least two nameservers all map to one ASN. This is routing-origin evidence, not proof of shared physical infrastructure, and it does not affect the grade. DNS or budget failures remain inconclusive.

### Scores, findings, and remediation

The dashboard provides an email score and a weighted overall posture score. The overall score is a rule-based summary of configured factors, not a probability of compromise or a guarantee of safety. The breakdown shows factors, weights, check states, and score adjustments. Not-applicable and wholly inconclusive factors are excluded; inconclusive checks in a partially observed factor receive neutral 50% credit. A grade may be marked provisional when too much factor weight is excluded. Either A or AAAA resolution satisfies the address-resolution score check; the scanner does not require dual-stack service. See [score details](../README.md#what-it-checks).

Findings use severity labels (`error`, `warning`, `info`, `inconclusive`) and may carry codes and explanations. Inconclusive means the check did not establish presence or absence. An informational finding can describe positive evidence or a limitation. Read its message and the underlying module status rather than treating the severity count as a pass/fail total. Remediation items are drafts for review; the scanner does not change DNS provider records. SPF advice intentionally asks the domain owner to confirm mail senders before creating a policy.

## Optional scoped network checks

These checks are separate from the full domain scan and do not crawl a site.

### DNS-only list scan

Accepts up to 50 hostnames or IP addresses and checks public scope. For hostnames it resolves A and AAAA records and reports per-family results. Each target is marked `in_scope`, `blocked`, `invalid`, `unresolved`, or `inconclusive`. A target is considered in scope only when the scanner has sufficient public-address evidence. Empty answers are different from DNS timeouts or budget exhaustion. This mode sends no port probes and makes no HTTP requests.

### Common web paths

Accepts up to five targets. After public-address checks, it requests seven fixed paths: `/robots.txt`, `/sitemap.xml`, `/security.txt`, `/.well-known/security.txt`, `/humans.txt`, `/manifest.json`, and `/favicon.ico`. It also reads bounded `robots.txt` and sitemap data and may check up to three additional same-origin sitemap paths. Advertised paths are listed for manual review; it does not automatically fetch every advertised URL or crawl directories. Results such as available, redirect, restricted, not found, unavailable, and inconclusive describe the observed HTTP response, not the sensitivity or exploitability of the content.

### Active port verification

This check makes TCP connection attempts to a bounded set of standard service ports (or a caller-supplied list within the server limit). Defaults are 22 (SSH), 25/465/587 (mail), 53 (DNS), 80 (HTTP), 443 (HTTPS), and 8443 (alternate HTTPS). It is disabled by default and requires server-side policy, an authorization token and/or approved target scope, and explicit request confirmation. Non-public targets are blocked. Results classify attempted ports as open, closed, or filtered; a timeout can mean filtering or an unresponsive service. Run it only against systems you own or are authorized to assess.

## Reading statuses correctly

DNS record results commonly use these states:

| State | Meaning |
|---|---|
| `ok` | A response with records of the requested type was received. |
| `no_answer` | The name responded, but no record of that type was returned. |
| `nxdomain` | DNS reported that the queried name does not exist. |
| `timeout`, `no_nameservers`, `error` | The query did not establish whether the requested record exists. |
| `budget_exhausted` | The scanner stopped because its work limit was reached; the result is unknown. |

Other modules use additional states such as `partial`, `unavailable`, `blocked`, `inconclusive`, `candidate`, `valid`, or `not_configured`. Their exact meanings depend on the check described above. In particular, **unavailable or inconclusive is not the same as absent**, and **no finding is not proof that a vulnerability does not exist**.

Scans use current public DNS and network responses. DNS propagation, resolver behavior, provider outages, firewalls, geography, and configuration changes can affect results. Review evidence, timestamps, coverage, and limitations before making operational changes.

The product does not currently provide RDAP/WHOIS expiry checks, server-side scan history, scheduled monitoring, or alert delivery. Dashboard scan history is stored in the current browser only. The main scan also does not send email or perform exploit attempts.
