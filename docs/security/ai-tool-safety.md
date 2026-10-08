# AI tool safety (Prompt 36 §26–§35)

## Why a closed catalog

An AI that can name its tools can be talked into naming dangerous
ones. The gateway catalog is therefore closed and typed: 27 tools in
five risk classes (READ, ANALYZE, PLAN, SAFE_ACTION,
RESTRICTED_ACTION). Names like runShellCommand, executeSql,
kubectlExec, runFridaScript and exploitFinding do not exist and are
refused with UNKNOWN_TOOL — a refusal that is itself audited.

## Argument safety (§29)

Arguments validate against per-tool schemas; extra/unknown fields
are REJECTED rather than ignored, so a poisoned plan cannot smuggle
parameters (hosts, commands, flags) past the gate.

## Rate limits and loops (§35/§58)

Per-tool hourly call ceilings per user/workspace; agent runs detect
repeated identical call signatures (threshold 3) and terminate.
Budgets (per-task and monthly) are enforced before provider calls.
