# DNS Analyzer — project review and "one scan" design report

**Version reviewed:** 2.2.0 (`main`, commit `7f19ac7`)
**Scope:** architecture, scan pipeline, scan quality, and a concrete plan for a single consolidated deep scan.
**Method:** read the full `app/` pipeline, routes, CLI, models, budgets and docs; ran the test suite and the same Ruff selection CI uses.

| Check | Result |
|---|---|
| `./venv/bin/pytest -q` | **335 passed** in 37.25s |
| `ruff check app tests --select E4,E7,E9,F` | **All checks passed** |
| Test surface | 25 `test_*.py` files (28 test-related files with fixtures), ~8.8k LOC in `app/` |
| Packaging | `pyproject.toml` entry points, Docker test stage, hash-locked requirements |

---

## TL;DR

The product is in good shape: one shared pipeline, honest "inconclusive" semantics, strong SSRF/authorization hygiene, stable finding codes, SARIF, and a real test suite. The gap is not check coverage — it is that **"a scan" is not a single contract**. The full scan, custom DKIM selectors, common web paths, and active port checks are four separate code paths with four separate budgets and caches, and the result object reports the optional ones as `not_run` even after they have been run.

To get one scan with great scans, make five changes:

1. **Add `ScanOptions` and `run_scan(domain, options)`**; keep `run_full_scan(domain)` as the default-profile wrapper so nothing breaks.
2. **Turn every optional check into a stage with declared dependencies** and run all stages inside the same pipeline (paths, ports, custom DKIM selectors included).
3. **Replace the hardcoded `not_run` coverage entries** (`app/main.py:349-350`) with a real per-stage result contract (`complete | partial | inconclusive | not_requested | skipped_policy | blocked | error`) that carries source, reason, duration, and cache provenance.
4. **Key caches and the grade by `(domain, options)`**, and return a **partial result at the deadline** instead of a `504`.
5. **Let budgets borrow** unused capacity, and surface per-stage timing/budget usage so "deep" is measurable rather than aspirational.

Estimated effect: one request instead of up to five, no duplicate DNS/HTTP work, a grade that explains what was actually measured, and a UI where "what ran" is always true.

---

## 1. What the project is

DNS Analyzer audits a domain's public DNS, email authentication, DNSSEC delegation, TLS/web posture, CT-discovered subdomains, takeover indicators, authoritative DNS posture, RDAP expiry, RPKI route status, DANE/TLSA, SMTP STARTTLS, and MX DNS blacklists. It ships a FastAPI dashboard, a Python CLI, a JSON API, SARIF output, and an offline HTML report.

**Stack:** Python 3.11+, FastAPI, dnspython, Pydantic v2, Jinja2, httpx, cryptography, vanilla JS. No database, no job queue, no accounts — deliberately.

### Architecture (one page)

```text
              ┌──────────────────────────────┐
  CLI ───────►│ run_full_scan(domain)        │◄─────── POST /api/analyze
              │ app/main.py:404              │         POST /api/analyze/batch
              └──────────────┬───────────────┘
                             │
   1. resolve_domain ────────┤ A/AAAA/MX/NS/TXT/CNAME/SOA/CAA + zone apex
   2. analyze(records) ──────┤ rule-based findings (10 checks)
   3. SPF ───────────────────┤ parse + lookup count + safe flatten (concurrent pair)
   4. core gather ───────────┤ DMARC, DKIM, DNSSEC, takeover, TLS/HTTP,
                             │ CT subdomains, MTA-STS/TLS-RPT, AXFR, wildcard,
                             │ NS consistency, NS ASN diversity (11 tasks)
   5. parent/child ──────────┤ depends on step 4 NS consistency
   6. BIMI ──────────────────┤ depends on step 4 DMARC
   7. plugins ───────────────┤ domain_lifecycle (RDAP), extended_security
                             │   (RPKI, TLSA, STARTTLS, DNSBL)
   8. score + remediation ───┤ weighted factors, caps, provisional grade
   9. coverage + response ───┘
```

**Important properties already in place**

- One service function (`run_full_scan`) is shared by API and CLI (`app/cli.py:98-101`), so behavior does not fork.
- Every outbound query goes through `ScanWorkBudget` module shares (`app/work_budget.py`) and a budgeted resolver; exhaustion is a typed exception.
- Independent checks are isolated: `_isolated_data_check` / `_isolated_pair_check` (`app/main.py:390-401`) turn a crash or timeout into an `inconclusive` finding instead of failing the scan.
- Plugins are discovered from `app/checks/` and the `dns_analyzer.checks` entry-point group (`app/check_registry.py`), with per-plugin timeouts and output under `extensions`.
- SSRF defenses are unusually thorough: public-IP validation, pinned-IP HTTP transport, redirect and method limits, target cooldown, API keys, and explicit authorization gates for active checks.
- Findings have a catalog-backed stable code (`app/finding_catalog.py`), `why/fix` explanations, remediation drafts, and BIND export.
- The docs are candid about limitations. That is rare and it is a real asset.

---

## 2. How a scan runs today — and where it splits

### 2.1 The single-request path

`run_full_scan` is a **fixed sequence with a fixed feature set**. The request model is only:

```python
class AnalyzeRequest(BaseModel):      # app/models.py:27
    domain: str
    force_refresh: bool = False
```

There is no profile, no optional-stage flag, and no per-action authorization in the body. The CLI exposes `--json`, `--sarif`, `--min-grade`, `--require-complete` (`app/cli.py:104-118`) and nothing else.

### 2.2 What is inside vs. outside the scan

| Capability | In `run_full_scan`? | Where it runs instead |
|---|---|---|
| DNS records, CAA, zone apex | ✅ | — |
| SPF, DMARC, DKIM (15 built-in selectors) | ✅ | — |
| DNSSEC delegation (chain opt-in) | ✅ | env flag |
| TLS, HSTS/CSP/cookies, methods, security.txt | ✅ | — |
| CT subdomains, takeover, MTA-STS/TLS-RPT | ✅ | — |
| AXFR, wildcard, NS consistency, NS ASN, parent/child | ✅ | — |
| RDAP expiry | ✅ via plugin | — |
| RPKI, DANE/TLSA, SMTP STARTTLS, MX DNSBL | ✅ via plugin | — |
| **Custom DKIM selectors** | ❌ | `POST /api/email/dkim-selectors` |
| **Common web paths (7 or 64)** | ❌ | `POST /api/network/path-scan` |
| **Active TCP / Nmap ports** | ❌ | `POST /api/network/port-scan` |
| DNS-only target list | ❌ (by design) | `POST /api/network/list-scan` |

### 2.3 The consequences

1. **Coverage lies.** `_build_scan_coverage` hardcodes:

   ```python
   result.append(item("Common web paths", "not_run", "Run separately from Network & Scope"))  # app/main.py:349
   result.append(item("Active port probes", "not_run", "Opt-in and controlled by server policy"))  # :350
   ```

   Even after a standalone path scan succeeded, `/api/analyze` still says `not_run`. Only `/api/report/{domain}` patches that one string from a 900s cache (`app/main.py:928`), and it does so by exact name match.

2. **Duplicate work.** A path scan runs its own `ScanWorkBudget`, its own resolver, and re-resolves the target; the full scan already resolved A/AAAA seconds earlier. Custom DKIM runs its own budget and is merged into the report only if the cache happens to be warm.

3. **Five requests, five rate-limit hits, five cooldowns.** The dashboard needs separate user actions in different tabs, and each action consumes the expensive-endpoint budget (`DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN`, default 10/min).

4. **The report is stitched together.** `build_report` receives a scan plus optional `path_scan` and merged custom DKIM, so the artifact can contain results from different points in time with a single `scan_timestamp`.

---

## 3. Review findings

Prioritized by impact on the "one great scan" goal. Line numbers are for 2.2.0.

### P1 — The scan has no options contract

`run_full_scan(domain)` and `AnalyzeRequest` cannot express "include paths", "include ports", "check these selectors", or "I hold authorization". Everything optional has to be bolted on by the caller. Any consolidation without this contract becomes a pile of booleans in the route layer.

### P1 — Coverage is hand-assembled and inconsistent

`_build_scan_coverage` (`app/main.py:307-379`) derives each row from a different ad-hoc key per module (`status`, `scanned`, `security_headers is None`, `http_methods.status`), and the plugin loop title-cases dict keys. There are three vocabularies (record statuses, module statuses, coverage statuses) with no single source of truth, so the UI, report, and score can disagree about whether a check ran.

### P1 — Caches are keyed by domain only

`_get_cached_scan` / `_store_cached_scan` (`app/main.py:132-149`) key on the domain with a flat 60s TTL. The badge cache does too. As soon as a deep scan exists, a shallow scan can be served for a deep request (or vice versa) for up to a minute. `force_refresh` is the only escape hatch and it is client-controlled.

### P1 — Extension evidence does not affect the grade

`extension_findings` (RPKI, TLSA, STARTTLS, DNSBL, RDAP) are merged into `all_findings` (`app/main.py:589`) but are **not** passed to `compute_domain_score` (`module_findings=...`, `app/main.py:552`). Only their count of inconclusive results is added (`:594-595`). So a domain with an invalid RPKI origin or a DNSBL-listed MX keeps the same grade. That may be intentional, but it is undocumented in the score breakdown and it is not visible in `score_breakdown`.

### P2 — Fixed module shares prevent a true deep scan

`DNS_MODULE_SHARES` and `HTTP_MODULE_SHARES` (`app/work_budget.py:13-22`) reserve capacity and **never borrow** ("Unused module shares are not borrowed", `docs/DEPLOYMENT.md`). A domain with many MX hosts, 40 CT names, or several plugins can exhaust a small share and report `inconclusive` while the global 500-query budget is largely unused. Deep profiles will hit this immediately.

### P2 — The latency tail can turn into a total failure

The pipeline is `records → SPF (≤12s) → 11-way gather (≤18s) → parent/child (≤18s) → BIMI → plugins (≤12s)`. Only the outer 60s `wait_for` guards it (`app/main.py:679`). When the tail overruns, `_analyze_domain` raises `504` and **all completed work is discarded**, rather than returning what finished. There is also a mismatch: core checks get 18s but the `extended_security` plugin gets 12s (`app/check_registry.py:87`) while performing RPKI HTTP, TLSA handshakes, SMTP STARTTLS, and up to 21 DNSBL queries.

### P2 — Concurrency limits are per-process and can starve

`SCAN_SEMAPHORE = asyncio.Semaphore(8)` with a 3s queue wait and a 60s hold (`app/main.py:102-106`). `/api/analyze/batch` accepts 8 domains and fans out into the same semaphore (`app/main.py:695-712`), so one batch can occupy every slot. A deep profile that adds paths/ports inside the scan will make this worse unless it gets its own admission policy.

### P2 — CLI cannot reproduce a deep scan

The CLI is the natural CI surface, but it has no `--profile`, `--paths`, `--ports`, `--selectors`, `--timeout`, or `--fail-on-inconclusive`. A CI job therefore cannot run the same consolidated audit the dashboard can, and cannot gate on incomplete coverage except via `--require-complete`.

### P3 — Evidence and determinism gaps

- `_check_failure` (`app/main.py:381-388`) collapses "target did not answer", "timeout", and "our code raised" into one `inconclusive` finding with no machine-readable reason, while logging the traceback only server-side.
- Fallback dictionaries are duplicated per check in `run_full_scan`; adding a stage means editing the pipeline, the fallback, the coverage builder, the score call, and the report.
- Findings are not deduplicated or sorted before summary/export, so repeated module findings can inflate counts and make SARIF ordering unstable.
- Stage timestamps do not exist; only one `scan_timestamp`, while caches have different TTLs (scan 60s, paths 900s, custom DKIM 900s).
- `analyze()` special-cases one check by function identity (`app/analyzer.py:217-223`), which blocks any future per-check arguments.

### P3 — `app/main.py` is a 1,000-line mix of concerns

Routes, rate limiting, scan cache, badge SVG, report assembly, and the entire pipeline live in one module. This is the main obstacle to threading options cleanly. It is not urgent, but extracting `scan_pipeline.py`, `cache.py`, and `limits.py` will make the consolidation diff small and reviewable.

---

## 4. Target design: one scan, explicit stages

### 4.1 Options contract

Add to `app/models.py` (all defaults preserve today's behavior):

```python
class ScanOptions(BaseModel):
    profile: Literal["quick", "standard", "deep", "max"] = "standard"
    include_paths: bool = False
    path_mode: Literal["standard", "wide"] = "standard"
    include_ports: bool = False
    port_scanner: Literal["connect", "nmap"] = "connect"
    include_active_checks: bool = False        # must be true for ports/wide paths
    custom_dkim_selectors: list[str] = Field(default_factory=list, max_length=20)
    include_passive_ct: bool = True
    include_core_plugins: bool = True
    include_extended_plugins: bool = True
    include_extended_in_score: bool = False
    deadline_seconds: float | None = None
    allow_partial: bool = True

    def fingerprint(self) -> str:              # cache key component
        return hashlib.sha256(self.model_dump_json(exclude={"deadline_seconds"}).encode()).hexdigest()[:16]
```

Keep `AnalyzeRequest` as the wire model and add `options: ScanOptions = ScanOptions()`. Add `options` to `AnalyzeResponse` so a consumer can see exactly what was requested, and keep it out of the cache fingerprint only for secrets (there are none in `ScanOptions`; tokens stay in headers).

### 4.2 One entry point, many entry sizes

```python
async def run_scan(domain: str, options: ScanOptions | None = None) -> AnalyzeResponse: ...

async def run_full_scan(domain: str) -> AnalyzeResponse:      # backwards compatible
    return await run_scan(domain, ScanOptions())
```

Then make the existing standalone endpoints **thin wrappers** over `run_scan` with a narrow profile, so there is one implementation of each check:

| Route | Becomes |
|---|---|
| `POST /api/email/dkim-selectors` | `run_scan(domain, ScanOptions(profile="quick", include_core_plugins=False, custom_dkim_selectors=...))` and return only the DKIM slice |
| `POST /api/network/path-scan` | `run_scan(..., options with include_paths=True)` and return the path slice |
| `POST /api/network/port-scan` | `run_scan(..., include_ports=True, include_active_checks=True)` and return the port slice |
| `GET /api/subdomains/{domain}` | `profile="quick"` with only CT enabled |

This keeps the routes working while eliminating the second budget/resolver/cache per feature.

### 4.3 Stage graph instead of a hard-coded sequence

Represent every check as a stage with declared inputs:

```python
@dataclass(frozen=True)
class Stage:
    name: str
    run: Callable[..., Awaitable[tuple[Any, list[Finding]]]]
    requires: frozenset[str] = frozenset()
    budget_module: str = "shared"
    timeout: float = 18.0
    enabled: Callable[[ScanOptions], bool] = lambda _: True
    optional: bool = True
```

Run in topological waves with `asyncio.gather(..., return_exceptions=True)`:

- **Wave 0 (no outbound):** normalize, validate, scope/authorization preflight, build the budget.
- **Wave 1:** `records` (required by everything).
- **Wave 2:** `spf`, `dnssec`, `dkim`, `tls`, `takeover`, `subdomains`, `mail_transport`, `axfr`, `wildcard`, `ns_consistency`, `ns_asn`, `rdap`, `rpki`, `dnsbl`, `starttls` — all only need the domain, resolver, records, or budget.
- **Wave 3:** `dmarc` → `bimi`; `ns_consistency` → `parent_child`; `records.MX` → `tlsa`; `records.A/AAAA` → `paths`; `authorization` → `ports`.
- **Wave 4:** aggregate, dedupe, score, remediation, coverage, response.

Notes:

- `TLSA` currently lives inside the `extended_security` plugin and needs `MX`; `DNSBL` and `STARTTLS` do too. Splitting them into their own stages lets them start in wave 2/3 instead of waiting behind RPKI. This also fixes the 12s plugin timeout issue.
- `records` is already collected before the gather, so `MX` is available: TLSA/DNSBL/STARTTLS can join wave 2. `BIMI` and `parent_child` genuinely depend on earlier results and stay in wave 3.
- Plugins remain supported: the registry maps each entry point to a stage named after the plugin, with `requires=frozenset({"records"})`, so third-party checks still work and can declare dependencies later via an optional `requires` attribute.

### 4.4 Per-stage result contract

One type used by coverage, score, UI, and report:

```python
class StageResult(BaseModel):
    name: str
    status: Literal["complete", "partial", "inconclusive", "not_requested",
                    "skipped_policy", "blocked", "error"]
    reason: str | None = None
    source: str | None = None          # e.g. "crt.sh", "RIPEstat", "direct NS"
    duration_ms: int | None = None
    cached: bool = False
    budget_used: dict[str, int] = Field(default_factory=dict)
```

`coverage` becomes `list[StageResult]` (the dashboard already renders `name/status/detail`, so keep a compatibility `detail` field derived from `reason`). This removes the `not_run` literals and the exact-name patching in `app/main.py:928`.

**Status rules (worth encoding as tests):**

- `not_requested` — the options did not ask for it (never shown as a failure).
- `skipped_policy` — requested but the server disallows it (e.g., active ports disabled).
- `blocked` — SSRF/scope refusal.
- `inconclusive` — ran, but did not establish presence or absence.
- `error` — the check itself failed unexpectedly (keep the sanitized message; add `reason="internal_error"` and a correlation id to the log).
- `partial` — some evidence collected, some missing.

### 4.5 Budgets that can actually go deep

Replace fixed shares with **soft shares plus a shared pool**:

1. Each module gets a guaranteed minimum (current shares scaled by profile).
2. When a module finishes, its unused share returns to a shared pool.
3. A module may borrow from the pool only while the global budget allows.
4. Report `budget_used` per stage and `budget_exhausted` as a first-class status.

Illustrative profiles (tune from measurements, not guesses):

| Profile | DNS | HTTP | Wall clock | Includes |
|---|---|---|---|---|
| `quick` | 120 | 6 | 20s | records, SPF/DMARC/DKIM, certificate summary |
| `standard` | 500 | 37 | 60s | today's full scan |
| `deep` | 900 | 90 | 90s | standard + custom selectors + 7-path scan + split TLSA/STARTTLS/DNSBL/RPKI |
| `max` | 1500 | 260 | 120s | deep + wide paths (160 HTTP) + Nmap top-100; requires `include_active_checks` and server policy |

Do not enable `max` by default. Active scanning policy (`ENABLE_ACTIVE_PORT_SCAN`, `PORT_SCAN_API_KEY`, `WIDE_PATH_SCAN_*`) remains the gate; the profile only requests it.

### 4.6 Deadlines and partial results

- Give each stage `min(stage.timeout, remaining_scan_deadline)`.
- Never let one stage abort the scan.
- If the deadline hits, cancel outstanding stages, mark them `inconclusive` with `reason="deadline"`, and return **200 with `scan_status="partial"`**. Reserve `504` for "nothing completed" (e.g., records resolution itself timed out and no stage produced data).
- Add `scan_status: complete | partial` and `stage_timings` to the response. This is the single biggest UX improvement for deep scans: a 90% answer beats a `504`.

### 4.7 Cache keys and freshness

```python
key = (domain, options.fingerprint())
ttl = {"quick": 30, "standard": 60, "deep": 300, "max": 900}[options.profile]
```

- Keep the bounded LRU behavior.
- Store `completed_at` per stage so a reused CT/path result is visible as `cached: true`.
- On a deep scan, reuse a same-domain result from another profile only for stages that are **identical and still fresh** (e.g., path scan cache 900s); never reuse the whole response across profiles.
- Badge and report read the standard/deep entry explicitly.
- `force_refresh` clears only the requested key.

### 4.8 Scoring

Do not silently fold new evidence into the grade. Two explicit choices:

- **Default:** expose `advisory` results (RPKI, DNSBL, DANE, RDAP) as a separate `advisory_score` and list them in `score_breakdown.excluded` with a reason.
- **Opt-in:** `include_extended_in_score=True` adds an `extended_posture` factor and rebalances weights; record `scoring_profile` in the breakdown so a grade is always reproducible from the response.

Also dedupe before scoring: `(code, record_type, message)`, then sort by severity → code → record_type. This fixes count drift and makes SARIF diffs stable.

### 4.9 API, CLI, and UI

**API**

- `POST /api/analyze` accepts optional `options` (backwards compatible).
- Add `GET /api/scan/profiles` (cheap, documented) so clients know what they may request and what the server currently allows.
- Batch stays 2–8 but should accept one shared `ScanOptions` and return per-domain `scan_status`.

**CLI**

```bash
dns-analyzer example.com --profile deep --paths --selectors selector1,google --json
dns-analyzer example.com --profile max --ports --confirm-active --sarif
dns-analyzer example.com --fail-on-inconclusive --min-coverage 0.9
```

Add `--profile`, `--paths [--wide]`, `--ports [--nmap]`, `--selectors`, `--confirm-active`, `--timeout`, `--fail-on-inconclusive`, `--out`. Keep exit-code semantics, add `5` for "coverage below threshold" if you add that gate.

**Dashboard**

- One primary **Run scan** action with a profile selector and an "Include active checks" panel (authorization token + confirmation, already built for the network tab).
- The Network tab stays for ad-hoc single-target checks but calls the same endpoint.
- Coverage panel renders the new statuses and per-stage duration; `not_requested` should look neutral, not like a gap.

---

## 5. What "great scans" means, concretely

The scanner already does the hard part: it refuses to turn "no answer" into "not present". Keep that as the organizing principle and enforce it structurally.

1. **One result type per stage.** Status, reason, source, evidence, duration, cache. No module-specific keys in coverage.
2. **Evidence before verdict.** Every finding carries the observed value, the method, and the timestamp. For takeover, keep the existing rule that only verified, dated fingerprints can confirm.
3. **Deterministic output.** Stable ordering, stable codes, single normalized timestamp per stage, sorted lists, no dict-order-dependent labels.
4. **Partial success is the default.** A scan always returns something; the response says what is missing and why.
5. **Bounded blast radius.** Authorization preflight before any active stage; per-target cooldown; separate admission for deep profiles; no redirect or cross-host escalation.
6. **Budget transparency.** Return what was used per stage. An `inconclusive` caused by budget exhaustion is different from one caused by an unreachable target, and users should see which.
7. **Freshness honesty.** A reused CT/path result is labeled `cached` with its own timestamp. Never present a 15-minute-old path scan as part of a fresh scan without saying so.
8. **Reproducibility.** `scan_options`, `scoring_profile`, and `scan_timestamp` are enough to explain any grade.
9. **Regression protection.** Snapshot the response shape; test the status matrix; fake the clock and the resolver for timeout tests; assert that adding a stage cannot change existing default responses.
10. **Observability.** One correlation id per scan in logs; counters for `inconclusive` by reason; histogram of stage durations and budget usage. Today only free-text logs exist.

---

## 6. Implementation plan

### Milestone 1 — Contract and compatibility (no behavior change)

- Add `ScanOptions`, `StageResult`, `scan_status`, `stage_timings` to `app/models.py`.
- Add `run_scan(domain, options)`; make `run_full_scan` a wrapper.
- Thread `options` through `_analyze_domain` and the CLI; keep defaults identical.
- Key `_SCAN_CACHE` by `(domain, options.fingerprint())`; keep the badge on the standard profile.
- Add response-shape and default-equivalence tests.

**Acceptance:** all 335 existing tests pass; a request with no options produces byte-identical `findings`, `summary`, and `domain_score` to 2.2.0.

### Milestone 2 — Truthful coverage

- Replace `_build_scan_coverage` with per-stage `StageResult` collection.
- Remove the two `not_run` literals; derive `not_requested` from options.
- Give plugins stable stage names and reuse the same result type.
- Update `app/report.py` and `static/app.js` to render the new statuses.
- Add a status-matrix test (requested/not requested/policy-disabled/blocked/error).

**Acceptance:** a scan that ran a path scan reports `complete` for paths; a scan that did not request ports reports `not_requested`, and the report matches the API.

### Milestone 3 — Consolidate the optional stages

- Split `extended_security` into `rpki`, `tlsa`, `starttls`, `dnsbl` stages (keep the plugin entry point as a compatibility shim).
- Run custom DKIM selectors, the standard 7-path scan, and (policy permitting) the port scan inside `run_scan` when requested.
- Add the stage graph with `requires`, per-stage deadlines, and partial results.
- Make the standalone routes thin wrappers over `run_scan`.
- Deduplicate and sort findings before scoring/export.

**Acceptance:** one `POST /api/analyze` with `profile="deep"` returns records, email, security, TLS, subdomains, posture, extensions, paths, and ports; the dashboard needs one click; no duplicate CT/DNS work for paths.

### Milestone 4 — Deep budgets, scoring boundary, and operations

- Implement borrowing budgets and per-stage `budget_used`.
- Add `advisory_score` and the opt-in `extended_posture` factor.
- Add `--profile/--paths/--ports/--selectors/--fail-on-inconclusive` to the CLI.
- Separate admission for deep profiles (e.g., deep scans take a weighted slot).
- Update `README.md`, `docs/scan.md`, `docs/API.md`, `docs/DEPLOYMENT.md`, `PROGRESS.md`, and `CHANGELOG.md`.
- Add metrics/log correlation and a benchmark script for stage durations.

**Acceptance:** a `deep` scan completes under its profile deadline with no `504`; `budget_exhausted` is visible per stage; a `max` scan is refused cleanly when policy does not allow it.

---

## 7. Risks and non-goals

**Risks**

- **Grade churn.** Any scoring change moves grades. Keep extended evidence out of the grade by default and make the change opt-in, as above.
- **Latency and abuse surface.** Folding active checks into a scan increases outbound work. Keep active stages opt-in, authorized, and separately admitted; never let `deep` imply permission.
- **Cache correctness.** A profile-aware cache is easy to get subtly wrong. Add tests for cross-profile isolation and TTL boundaries; keep `force_refresh` per key.
- **Plugin compatibility.** Third-party plugins pass `(domain, resolver, budget, records)`. Keep that call signature; extend it with an optional keyword (`options`) rather than changing positional arguments.
- **Refactor temptation.** Do not rewrite `main.py` in the same change as the contract. Extract modules only when Milestone 3 needs it, or the review diff becomes unreviewable.

**Non-goals**

- No crawling or unbounded directory discovery. Path mode stays fixed and bounded.
- No exploitation, credential testing, or UDP scans.
- No server-side scheduler, accounts, or alerting in this work. That is a separate product decision.
- No multi-worker shared state yet. Document that caches and limits are per process; move to a shared store only if deployment requires it.

---

## 8. Quick reference: files to touch

| Concern | File |
|---|---|
| Options, response contract | `app/models.py` |
| Pipeline, stage graph, coverage | `app/main.py` (extract to `app/scan_pipeline.py` when it grows) |
| Budgets and borrowing | `app/work_budget.py` |
| Plugin stages, stable names | `app/check_registry.py`, `app/checks/*` |
| Split extended plugin | `app/extended_checks.py` |
| Path/port reuse | `app/network_scan.py` |
| Custom selectors | `app/email_auth.py` |
| Scoring boundary | `app/email_auth.py` (`compute_domain_score`) |
| Report rendering | `app/report.py`, `static/app.js`, `static/index.html` |
| CLI | `app/cli.py` |
| Docs | `README.md`, `docs/scan.md`, `docs/API.md`, `docs/DEPLOYMENT.md`, `PROGRESS.md`, `CHANGELOG.md` |

---

*Prepared from the 2.2.0 source tree; test and lint results were produced in this environment.*
