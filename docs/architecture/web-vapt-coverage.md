# Web VAPT Coverage (Prompt 32 §146–§151)

Coverage is the report's limitations section, computed from what was
actually tested (`packages/security-sdk/src/webvapt/coverage.ts`):

- discovered vs tested endpoints, parameters, and authenticated
  endpoints (ratios are `null` when the denominator is zero — "not
  measured", never 100%);
- tool coverage: planned vs contributed vs silent tools;
- every skipped test with its reason (`AUTHORIZATION`, `POLICY_BLOCKED`,
  `AUTHENTICATION_FAILED`, `TOOL_UNAVAILABLE`, `BUDGET_EXHAUSTED`,
  `NOT_APPLICABLE`);
- a limitations list assembled from budget exhaustion, failed stages
  and skips.

Terminal status derives from the same numbers: budget exhaustion,
skips or stage failures produce `COMPLETED_WITH_GAPS`; hard stage
failure produces `FAILED`; parser failure is partial/error — never
clean (§145/§188).

**No report, dashboard or export may claim a target is "100% secure"
(§148).** The coverage record exists precisely so that sentence can
never be written by accident.

## Tool health (§146)

`WebToolHealth` records per workspace: installed, version, last
successful run, error rate, parser compatibility. The health view
derives `HEALTHY` / `DEGRADED` / `UNAVAILABLE`; unrecorded tools are
UNAVAILABLE — health is never fabricated.
