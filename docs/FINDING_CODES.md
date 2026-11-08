# Finding condition codes

Each row is a condition rule used to assign a finding code. Legacy alias is the earlier broad record-type code retained for existing consumers; `—` means no earlier distinct code existed.

| Module/type | Condition marker | Stable code | Legacy alias |
|---|---|---|---|
| GENERAL | `does not resolve to any ip address` | `DNS-RESOLVE-001` | `DNS-001` |
| NS | `no nameservers found` | `DNS-NS-001` | `DNS-004` |
| NS | `only one nameserver` | `DNS-NS-003` | `DNS-004` |
| NS | `does not resolve` | `DNS-NS-004` | `DNS-004` |
| NS | `operates under authoritative zone` | `DNS-NS-005` | `DNS-004` |
| MX | `no mx records found` | `MAIL-MX-001` | `MAIL-001` |
| MX | `does not resolve` | `MAIL-MX-002` | `MAIL-001` |
| CNAME | `coexists with other record types` | `DNS-CNAME-001` | `DNS-005` |
| SOA | `no soa record found` | `DNS-SOA-001` | `DNS-006` |
| SOA | `refresh interval` | `DNS-SOA-002` | `DNS-006` |
| SOA | `expire value` | `DNS-SOA-003` | `DNS-006` |
| CAA | `no caa issuance policy` | `DNS-CAA-002` | `CERT-001` |
| CAA | `explicitly forbids certificate issuance` | `DNS-CAA-003` | `CERT-001` |
| CAA | `restricts certificate issuance to` | `DNS-CAA-004` | `CERT-001` |
| A | `ttl of 0` | `DNS-TTL-001` | `DNS-002` |
| AAAA | `ttl of 0` | `DNS-TTL-001` | `DNS-003` |
| MX | `ttl of 0` | `DNS-TTL-001` | `MAIL-001` |
| NS | `ttl of 0` | `DNS-TTL-001` | `DNS-004` |
| CNAME | `ttl of 0` | `DNS-TTL-001` | `DNS-005` |
| TXT | `ttl of 0` | `DNS-TTL-001` | `DNS-007` |
| CAA | `ttl of 0` | `DNS-TTL-001` | `CERT-001` |
| SOA | `ttl of 0` | `DNS-TTL-001` | `DNS-006` |
| A | `ttl on `a` record is unusually high` | `DNS-TTL-002` | `DNS-002` |
| AAAA | `ttl on `aaaa` record is unusually high` | `DNS-TTL-002` | `DNS-003` |
| MX | `ttl on `mx` record is unusually high` | `DNS-TTL-002` | `MAIL-001` |
| NS | `ttl on `ns` record is unusually high` | `DNS-TTL-002` | `DNS-004` |
| CNAME | `ttl on `cname` record is unusually high` | `DNS-TTL-002` | `DNS-005` |
| TXT | `ttl on `txt` record is unusually high` | `DNS-TTL-002` | `DNS-007` |
| CAA | `ttl on `caa` record is unusually high` | `DNS-TTL-002` | `CERT-001` |
| SOA | `ttl on `soa` record is unusually high` | `DNS-TTL-002` | `DNS-006` |
| SPF | `no spf record found` | `MAIL-SPF-001` | `MAIL-002` |
| SPF | `multiple spf records found` | `MAIL-SPF-002` | `MAIL-002` |
| SPF | `exceeding the rfc 7208` | `MAIL-SPF-003` | `MAIL-002` |
| SPF | `approaching the` | `MAIL-SPF-004` | `MAIL-002` |
| SPF | `has no 'all' mechanism` | `MAIL-SPF-005` | `MAIL-002` |
| SPF | `uses '+all'` | `MAIL-SPF-006` | `MAIL-002` |
| SPF | `uses '?all'` | `MAIL-SPF-007` | `MAIL-002` |
| SPF | `uses '~all'` | `MAIL-SPF-008` | `MAIL-002` |
| SPF | `uses '-all'` | `MAIL-SPF-009` | `MAIL-002` |
| SPF | `deprecated 'ptr' mechanism` | `MAIL-SPF-010` | `MAIL-002` |
| SPF | `characters long, exceeding` | `MAIL-SPF-011` | `MAIL-002` |
| DMARC | `could not be verified` | `MAIL-DMARC-005` | `MAIL-003` |
| DMARC | `policy is inherited` | `MAIL-DMARC-006` | `MAIL-003` |
| DMARC | `policy is 'quarantine'` | `MAIL-DMARC-007` | `MAIL-003` |
| DMARC | `policy is 'reject'` | `MAIL-DMARC-008` | `MAIL-003` |
| DMARC | `no subdomain policy` | `MAIL-DMARC-009` | `MAIL-003` |
| DKIM | `checks were inconclusive` | `MAIL-DKIM-001` | `MAIL-004` |
| DKIM | `could not be fully verified` | `MAIL-DKIM-002` | `MAIL-004` |
| DKIM | `no dkim records detected` | `MAIL-DKIM-003` | `MAIL-004` |
| DKIM | `has an empty public key` | `MAIL-DKIM-004` | `MAIL-004` |
| DKIM | `is in testing mode` | `MAIL-DKIM-005` | `MAIL-004` |
| DKIM | `is configured for selector` | `MAIL-DKIM-006` | `MAIL-004` |
| DNSSEC | `could not be verified` | `DNSSEC-002` | `DNSSEC-001` |
| DNSSEC | `without usable digest data` | `DNSSEC-003` | `DNSSEC-001` |
| DNSSEC | `does not match` | `DNSSEC-004` | `DNSSEC-001` |
| DNSSEC | `none match the zone` | `DNSSEC-004` | `DNSSEC-001` |
| DNSSEC | `without matching zone dnskey` | `DNSSEC-005` | `DNSSEC-001` |
| DNSSEC | `no ds delegation record` | `DNSSEC-006` | `DNSSEC-001` |
| DNSSEC | `not enabled` | `DNSSEC-007` | `DNSSEC-001` |
| DNSSEC | `ds record matches zone dnskey` | `DNSSEC-008` | `DNSSEC-001` |
| DNSSEC | `uses a sha-1 ds digest type` | `DNSSEC-009` | `DNSSEC-001` |
| DNSSEC | `uses a deprecated algorithm` | `DNSSEC-010` | `DNSSEC-001` |
| DNSSEC | `signature expires soon` | `DNSSEC-011` | `DNSSEC-001` |
| DNSSEC | `signature expired` | `DNSSEC-012` | `DNSSEC-001` |
| DNSSEC | `signature is not yet valid` | `DNSSEC-013` | `DNSSEC-001` |
| TAKEOVER | `potential dangling cname` | `TAKEOVER-002` | `TAKEOVER-001` |
| TAKEOVER | `unclaimed-service response fingerprint matched` | `TAKEOVER-003` | `TAKEOVER-001` |
| TAKEOVER | `could not be verified` | `TAKEOVER-004` | `TAKEOVER-001` |
| AXFR | `allowed an unauthenticated zone transfer` | `DNS-AXFR-002` | `DNS-AXFR-001` |
| WILDCARD DNS | `random hostname resolved` | `DNS-WILDCARD-002` | `DNS-WILDCARD-001` |
| WILDCARD DNS | `could not be evaluated` | `DNS-WILDCARD-003` | `DNS-WILDCARD-001` |
| NS CONSISTENCY | `could not obtain both soa and ns answers` | `DNS-NSCONS-001` | `DNS-NS-002` |
| NS CONSISTENCY | `different soa serial numbers` | `DNS-NSCONS-002` | `DNS-NS-002` |
| NS CONSISTENCY | `disagree on soa mname` | `DNS-NSCONS-003` | `DNS-NS-002` |
| NS CONSISTENCY | `different ns record sets` | `DNS-NSCONS-004` | `DNS-NS-002` |
| MTA-STS | `no mta-sts dns record` | `MAIL-MTASTS-002` | `MAIL-005` |
| MTA-STS | `policy file status is valid (mode=enforce)` | `MAIL-MTASTS-001` | `MAIL-005` |
| MTA-STS | `policy file status is valid` | `MAIL-MTASTS-003` | `MAIL-005` |
| MTA-STS | `policy file status is invalid` | `MAIL-MTASTS-004` | `MAIL-005` |
| MTA-STS | `policy file status is unavailable` | `MAIL-MTASTS-006` | `MAIL-005` |
| MTA-STS | `could not be verified` | `MAIL-MTASTS-005` | `MAIL-005` |
| TLS-RPT | `configured with` | `MAIL-TLSRPT-001` | `MAIL-006` |
| TLS-RPT | `no tls-rpt reporting record` | `MAIL-TLSRPT-002` | `MAIL-006` |
| TLS-RPT | `could not be verified` | `MAIL-TLSRPT-003` | `MAIL-006` |
| BIMI | `could not be verified` | `MAIL-BIMI-001` | `MAIL-007` |
| BIMI | `not configured` | `MAIL-BIMI-004` | `MAIL-007` |
| BIMI | `missing the required svg logo` | `MAIL-BIMI-002` | `MAIL-007` |
| BIMI | `record found, but dmarc policy` | `MAIL-BIMI-003` | `MAIL-007` |
| BIMI | `bimi is active` | `MAIL-BIMI-005` | `MAIL-007` |
| INVENTORY | `stream reached` | `RECON-CT-002` | `RECON-CT-001` |
| INVENTORY | `response exceeded` | `RECON-CT-003` | `RECON-CT-001` |
| INVENTORY | `could not be parsed` | `RECON-CT-004` | `RECON-CT-001` |
| INVENTORY | `returned http` | `RECON-CT-005` | `RECON-CT-001` |
| INVENTORY | `lookup failed` | `RECON-CT-006` | `RECON-CT-001` |
| INVENTORY | `limited to` | `RECON-CT-007` | `RECON-CT-001` |
| INVENTORY | `dns resolution was inconclusive` | `RECON-CT-008` | `RECON-CT-001` |
| SUBDOMAINS | `dangling cname pointers` | `RECON-SUB-002` | `RECON-SUB-001` |
| SUBDOMAIN TAKEOVER | `ct inventory found` | `TAKEOVER-005` | `TAKEOVER-002` |
| TLS | `ssrf safety guard` | `WEB-TLS-001` | `WEB-002` |
| TLS | `encountered an error` | `WEB-TLS-002` | `WEB-002` |
| TLS | `certificate verification failed` | `WEB-TLS-003` | `WEB-002` |
| TLS | `was inconclusive` | `WEB-TLS-007` | `WEB-002` |
| TLS | `certificate for` | `WEB-TLS-004` | `WEB-002` |
| TLS | `certificate expires soon` | `WEB-TLS-005` | `WEB-002` |
| TLS | `certificate is valid` | `WEB-TLS-008` | `WEB-002` |
| TLS | `san mismatch` | `WEB-TLS-006` | `WEB-002` |
| TLS | `modern encryption protocol` | `WEB-TLS-009` | `WEB-002` |
| TLS | `legacy or deprecated tls protocol` | `WEB-TLS-010` | `WEB-002` |
| HTTPS | `ssrf alert` | `WEB-HTTPS-001` | `WEB-001` |
| HTTPS | `automatically redirects to https` | `WEB-HTTPS-003` | `WEB-001` |
| HTTPS | `does not redirect to https` | `WEB-HTTPS-002` | `WEB-001` |
| HTTPS | `redirect check was inconclusive` | `WEB-HTTPS-004` | `WEB-001` |
| CSP | `common weaknesses` | `WEB-CSP-001` | `WEB-003` |
| CSP | `is present; common` | `WEB-CSP-003` | `WEB-003` |
| COOKIE | `observed cookie(s) miss` | `WEB-COOKIE-001` | `WEB-004` |
| HTTPS | `security header inspection on port` | `WEB-HEADERS-001` | `WEB-001` |
| HTTP METHODS | `advertises potentially sensitive` | `WEB-METHODS-001` | `WEB-005` |
| SECURITY.TXT | `security.txt is missing` | `WEB-SECURITYTXT-001` | `GEN-001` |
| SECURITY.TXT | `security.txt is malformed` | `WEB-SECURITYTXT-002` | `GEN-001` |
| SECURITY.TXT | `security.txt is expired` | `WEB-SECURITYTXT-003` | `GEN-001` |
| HTTPS | `additional browser isolation headers` | `WEB-HEADERS-002` | `WEB-001` |
| HTTPS | `port 80 http` | `WEB-HTTPS-005` | `WEB-001` |
| SPF LOOKUP COUNT | `check could not complete` | `SCAN-SPF-001` | `GEN-001` |
| SPF FLATTENING | `check could not complete` | `SCAN-SPF-002` | `GEN-001` |
| DNSSEC | `check could not complete` | `SCAN-DNSSEC-001` | `DNSSEC-001` |
| TAKEOVER | `check could not complete` | `SCAN-TAKEOVER-001` | `TAKEOVER-001` |
| TLS | `check could not complete` | `SCAN-TLS-001` | `WEB-002` |
| SUBDOMAINS | `check could not complete` | `SCAN-SUBDOMAINS-001` | `RECON-SUB-001` |
| MAIL TRANSPORT | `check could not complete` | `SCAN-MAIL-001` | `GEN-001` |
| AXFR | `check could not complete` | `SCAN-AXFR-001` | `DNS-AXFR-001` |
| WILDCARD DNS | `check could not complete` | `SCAN-WILDCARD-001` | `DNS-WILDCARD-001` |
| NS CONSISTENCY | `check could not complete` | `SCAN-NSCONS-001` | `DNS-NS-002` |
| DMARC | `check could not complete` | `SCAN-DMARC-001` | `MAIL-003` |
| DKIM | `check could not complete` | `SCAN-DKIM-001` | `MAIL-004` |
| BIMI | `check could not complete` | `SCAN-BIMI-001` | `MAIL-007` |
| HTTPS | `hsts is active` | `WEB-HSTS-001` | `WEB-001` |
| HTTPS | `content-security-policy (csp) header is not published` | `WEB-CSP-002` | `WEB-001` |
| HTTPS | `hsts header is missing` | `WEB-HSTS-002` | `WEB-001` |
| DMARC | `no dmarc policy` | `MAIL-DMARC-001` | `MAIL-003` |
| DMARC | `policy is set to 'none'` | `MAIL-DMARC-002` | `MAIL-003` |
| DMARC | `no aggregate report address (rua)` | `MAIL-DMARC-003` | `MAIL-003` |
| DMARC | `policy applies to only` | `MAIL-DMARC-004` | `MAIL-003` |

## Alias-only codes

These broad compatibility codes are not emitted as the primary `code`; matching findings retain them in `legacy_codes`.
`CERT-001`, `DNS-001`, `DNS-002`, `DNS-003`, `DNS-004`, `DNS-005`, `DNS-006`, `DNS-007`, `DNS-AXFR-001`, `DNS-NS-002`, `DNS-WILDCARD-001`, `DNSSEC-001`, `MAIL-001`, `MAIL-002`, `MAIL-003`, `MAIL-004`, `MAIL-005`, `MAIL-006`, `MAIL-007`, `RECON-CT-001`, `RECON-SUB-001`, `TAKEOVER-001`, `WEB-001`, `WEB-002`, `WEB-003`, `WEB-004`, `WEB-005`

## Reserved codes

None. Every catalog code is used as a primary code or a legacy alias.
