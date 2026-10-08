# Web VAPT Orchestration (Prompt 32 §12)

A V2 scan moves through a fixed pipeline:

```
PREFLIGHT → DISCOVERY → MAPPING → PASSIVE_ANALYSIS → SAFE_ACTIVE_TESTING
→ NORMALIZATION → CORRELATION → VERIFICATION → RISK → REPORT
```

Profiles select stage subsets; the order never changes. A stage may be
skipped only with a recorded skip reason (`AUTHORIZATION`,
`POLICY_BLOCKED`, `AUTHENTICATION_FAILED`, `TOOL_UNAVAILABLE`,
`BUDGET_EXHAUSTED`, `NOT_APPLICABLE`) — skips surface in the coverage
record and in the report's limitations.

## Lifecycle rules

- **Plan first (§10/§11):** the plan preview shows target, tools,
  stages, request budget, authentication profile reference and scope
  snapshot before any high-impact run starts.
- **Scope is frozen at start (§136/§137):** the snapshot hash is bound
  to the plan; mid-run scope changes apply to the *next* scan only.
  Newly discovered hosts are candidates, never scope (§138).
- **Budgets are hard (§48/§126/§127):** the `BudgetMeter` stops active
  stages gracefully at the ceiling; the scan derives
  `COMPLETED_WITH_GAPS`.
- **Cancellation (§128):** stages stop at checkpoints; partial results
  and evidence are preserved; the plan records `CANCELLED`.
- **Timeouts (§129):** per-tool timeouts from the adapter metadata;
  a timed-out tool is a gap, not a clean result (§187).
- **Status derivation (§150):** `deriveScanStatus` maps
  cancelled/blocked/failed/gaps to the honest terminal status —
  `FAILED`, `PARTIAL`, `COMPLETED_WITH_GAPS` or `COMPLETED`.

## Execution boundary

Adapters produce argv-only execution plans through the `ToolRunner`
boundary; binaries absent from the worker report UNAVAILABLE and are
never executed. Adapter commands are arrays — a target value containing
shell metacharacters is data in one argv element, never a command
(§131/§132/§193).
