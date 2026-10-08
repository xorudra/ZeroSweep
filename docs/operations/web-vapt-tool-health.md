# Web VAPT Tool Health (Prompt 32 §146)

The tool-health view (`GET /api/v1/vapt/tool-health`, Web VAPT page)
reports for each V2 tool: installed, version, last successful run,
error rate and parser compatibility, with a derived status:

- **HEALTHY** — installed, parser-compatible, low error rate.
- **DEGRADED** — installed but parser-incompatible (results would be
  partial) or error rate above 25%.
- **UNAVAILABLE** — not installed / not recorded. This is the honest
  default: the platform never fabricates health.

## Operating notes

- A tool whose binary is absent from the worker reports UNAVAILABLE
  and is never executed; plans that included it finish with the module
  skipped (`TOOL_UNAVAILABLE`) and the scan `COMPLETED_WITH_GAPS`.
- Parser compatibility matters as much as presence: an upgraded tool
  whose output format changed is DEGRADED until its parser is verified
  against recorded fixtures (§142–§144).
- Proxy connectors (Burp/Caido/ZAP) report capability-detected
  status from the Prompt 8 connector registry — a connector that is
  not configured is `NOT_CONFIGURED`, not broken (§62–§66).
