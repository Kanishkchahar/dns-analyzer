# Changelog

## 2.2.0

- Security hardening: maintain exact `httpx==0.28.1` and `httpcore==1.0.9` pins; sitemap XML parsing uses `defusedxml` and rejects entity payloads.
- Share a 500-DNS-query / 25-HTTP-fetch budget across full scans and optional network scan routes. Exhausted checks are reported as inconclusive.
- Add a configurable scanner User-Agent (`DNS_ANALYZER_DOCUMENTATION_URL`, defaulting to the editable placeholder URL).
- Use generic user-facing failure reasons while retaining diagnostic detail in server logs.
- Keep the port-scan JSON `auth_token` field for one release with a deprecation warning; `Authorization: Bearer` is the preferred credential transport.
- Document process/browser storage, logging, outbound DNS/CT/target requests, and their unconfigured retention limits.

- Exclude factors that are not applicable or have no completed checks, then normalize the remaining factor weights to 100.
- Mark the grade provisional when excluded factors exceed 30% of total weight; expose excluded factors and factor completion in the score breakdown.
- Document exact takeover-state deductions. Candidates deduct points but do not activate the confirmed-takeover cap.
- Unknown finding codes now log an error and use the generic code in production. Tests remain strict so module findings with uncatalogued codes fail the test suite.
- **Grades and `--min-grade` results may differ from earlier versions** because score normalization and incomplete-grade reporting changed.
