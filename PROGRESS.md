# Improvement Program Progress

Baseline before Phase 1: `./venv/bin/pytest -q` — **223 passed** (DNSSEC chain flag unset).

| Phase | Status | Test count | Note |
|---|---|---:|---|
| 0. Baseline and WIP checkpoint | DONE | 223 | Checkpoint includes the pre-existing `app/dns_posture.py` and `app/tls_check.py` changes. |
| 1. Repair the live DNSSEC path (review gate) | TODO | — | Restore Stage 2 semantics, use only “inconclusive”, and keep opt-in chain results out of scoring. |
| 2. Finish Stage 2 follow-up | TODO | — | Budget accounting, error leakage, token and privacy follow-up. |
| 3. Complete DNSSEC engine (review gate) | TODO | — | Parent DS handling, query flags, NSEC3, findings, anchors, cache, comparison script. |
| 4. DNSSEC score, response and UI (review gate) | TODO | — | Wait for score-rule approval before changing scoring. |
| 5. Frontend pass | TODO | — | Dashboard honesty, hierarchy, states and accessibility. |
| 6. Delegation, lifecycle and web checks | TODO | — | New informational checks with budgets, findings and tests. |
| 7. Storage, permanent reports, bulk (review gate) | TODO | — | Ask before selecting a retention default. |
| 8. Monitoring | TODO | — | Watches, scheduler, notifications and certificate inventory. |
| 9. Packaging and quality | TODO | — | CI, packaging, documentation, accuracy set and final verification. |

