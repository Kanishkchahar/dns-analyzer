# Decisions

## Phase 0

- The starting worktree contains extensive uncommitted project changes. Per the requested workflow, preserve all of it in the `work/dns-analyzer-improvements` WIP checkpoint before editing Phase 1.
- Baseline suite count is 223 passing tests with `ENABLE_DNSSEC_CHAIN_VALIDATION` unset.

## Phase 1

- DNSSEC states use `inconclusive` for unavailable or unprovable results. Chain-validator states remain informational until score rules are approved; legacy delegation observations retain their existing scoring behavior except where the restored classifications require safe handling.
- Legacy DS comparison is `bogus` only if at least one supported DS can actually be compared and all comparable DS records mismatch. If none can be compared, return `inconclusive`.
- A present DNSKEY RRset with no DS answer is reported as `incomplete_chain`; absence of both is `unsigned`.
- Stage 3 changed the live helper from independent DNSKEY/DS lookups to one combined try/except. It classified `NoAnswer` from either lookup as `unsigned`, and collapsed “no DS/DNSKEY match” into `bogus`. That erased the Stage 2 incomplete-chain and inconclusive outcomes. The fix separates lookup results and distinguishes comparable DS data from absent or unsupported data.
- With chain validation enabled, the response preserves the legacy `status` and adds `chain_status` for the new engine. The legacy delegation status is also retained as the score input. This keeps the opt-in validator informational and makes its state unable to change score, grade, or caps; it can still show its evidence in the response.
- Restored historical expectations in `test_dnssec_incomplete_chain`, `test_dnssec_ds_without_digest_is_inconclusive`, and `test_post_analyze_valid_domain`. Updated the former provisional chain-score regression to assert score/grade/caps are identical across chain states, as explicitly required; renamed it `test_chain_dnssec_states_are_informational_for_score_and_caps`.
- Added `test_dnssec_uncomparable_ds_is_inconclusive`, `test_enabled_chain_result_keeps_legacy_score_input`, and `test_every_dnssec_engine_state_has_the_expected_scoring_treatment`.
- Other expectations changed since the Stage 2 baseline reflect already-approved behavior: `test_network_path_scan_endpoint` now checks injected resolver/budget kwargs; `test_grade_badge_requires_a_recent_scan_and_serves_svg_after_scan` checks TTL-based expiry and incomplete-grade badges; `test_post_analyze_valid_domain` accepts provisional grade suffixes and checks score breakdown; the port-scan test was renamed to test one-release body-token deprecation; score tests in `test_email_auth.py` reflect approved factor weights, missing-check exclusion, and the AXFR cap of 54; `test_exact_http_fingerprint_confirms_takeover` became `test_unverified_http_fingerprint_is_candidate` because the catalog is explicitly unverified. These were not reverted because their behavior changes were separately approved.

