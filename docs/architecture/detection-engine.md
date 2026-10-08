# Detection Engine (Prompt 28 §14–§29)

## Rules

A `DetectionRule` is a declarative definition compiled by the SDK
DSL compiler (`packages/security-sdk/src/soc/dsl.ts`) into a typed
AST. Five types: `SINGLE_EVENT`, `THRESHOLD`, `SEQUENCE`,
`CORRELATION`, `ANOMALY_SIGNAL`. Conditions combine field predicates
(eq/neq/in/notIn/contains/numeric/CIDR/exists) over an allowlisted
field set — base event fields plus `attributes.<key>`.

**No code can exist in a rule (§18).** The compiler rejects any
definition containing shell/SQL/eval-shaped content (`eval`, `exec`,
backticks, `$(`, `${`, statement separators, comment markers),
unknown fields or operators, and anything beyond the complexity
limits (32 conditions, depth 4, sequence ≤ 8 steps, window 10 s–7 d,
threshold 2–10000, group cardinality 1000).

## Versioning & lifecycle (§15–§17, §111)

Rules are `DRAFT → TESTING → ACTIVE`, plus `DISABLED`/`DEPRECATED`.
Every edit creates a new immutable `DetectionRuleVersion`; the
version that produced a match is pinned on the `DetectionMatch`.
Activation stores nothing new — the stored version is re-compiled
at promotion, so what runs is exactly what was reviewed.

## Evaluation

Only ACTIVE workspace rules (plus global templates once seeded)
evaluate fresh telemetry. Threshold evaluation reports the most
recent satisfying window per group, and a match raises state only
when it involves the freshly stored event — historical replays
cannot manufacture alerts. Anomaly signals are z-scores against a
recorded baseline and always carry their explanation; an
insufficient baseline produces no signal. Detection confidence is
a deterministic function of rule type, severity, threshold evidence
and corroboration — never a model guess (§29).

## Templates & coverage (§25/§112–§114)

Fifteen built-in defensive templates ship as DRAFT rules with
MITRE ATT&CK mappings recorded as analyst context. Coverage counts
a technique as covered only when an ACTIVE, tested rule maps to it,
and the UI states plainly that **coverage is visibility, not
prevention**. Detection health flags rules with no data source,
high false-positive rates (from real triage rows), evaluation
failures, and stale matches. False positives never auto-disable a
rule (§38) — tuning is a human decision informed by the FP trend.
