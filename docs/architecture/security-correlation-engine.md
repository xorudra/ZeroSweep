# Security Correlation Engine (Prompt 27 §73–§82)

Correlation turns independent records into **reviewable signals**. It
never auto-escalates, never creates incidents on its own, and never marks
anything malicious — signals are evidence bundles for analysts.

## Rules

Rules are typed condition lists (`{field, op, value}`) evaluated by the
SDK over joined subject records (finding + asset + repository + control
context). Arbitrary expressions are rejected at the API (§75). Built-ins:

- `INTERNET_EXPOSED_KEV` — internet-facing asset with a KEV-listed finding.
- `CRITICAL_ASSET_CRITICAL_FINDING` — critical asset, critical open finding.
- `REPEATED_REGRESSION` — finding with repeated reopen cycles.
- `PUBLIC_CLOUD_CRITICAL` — public cloud resource with critical finding.
- `STALE_CRITICAL` — old unresolved critical finding.
- `CONTROL_FINDING_LINK` — failed control evaluation with linked findings.

## Signal lifecycle

Signals are upserted by a SHA-256 fingerprint of (rule, subject) —
re-running correlation **updates** `occurrenceCount`/`lastSeenAt` instead
of duplicating (§78). When the supporting evidence disappears, the signal
auto-resolves. Confidence derives from evidence completeness (verified
finding + exposure + intel linkage), not from a model's guess (§136/§137).
Analysts acknowledge/resolve signals via `PATCH /analytics/correlations/:id`.
