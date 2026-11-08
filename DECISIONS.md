# Decisions

## Phase 0

- The starting worktree contains extensive uncommitted project changes. Per the requested workflow, preserve all of it in the `work/dns-analyzer-improvements` WIP checkpoint before editing Phase 1.
- Baseline suite count is 223 passing tests with `ENABLE_DNSSEC_CHAIN_VALIDATION` unset.

## Phase 1

- DNSSEC states use `inconclusive` for unavailable or unprovable results. Chain-validator states remain informational until score rules are approved; legacy delegation observations retain their existing scoring behavior except where the restored classifications require safe handling.
- Legacy DS comparison is `bogus` only if at least one supported DS can actually be compared and all comparable DS records mismatch. If none can be compared, return `inconclusive`.
- A present DNSKEY RRset with no DS answer is reported as `incomplete_chain`; absence of both is `unsigned`.

