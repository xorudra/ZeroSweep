# Detection Rule Security (Prompt 28 §18, §134/§135)

Detection rules are data, never code. The DSL compiler
(`packages/security-sdk/src/soc/dsl.ts`) is the only path from a
stored definition to evaluation, and it enforces:

- **Closed grammar.** Condition nodes are `cond` / `all` / `any`
  over an allowlisted field set (canonical event fields and
  `attributes.<key>`) and a closed operator set. Unknown fields,
  operators or node kinds fail compilation with structured errors.
- **Injection refusal (§134).** Definitions containing
  shell/SQL/eval-shaped content — `eval`, `exec`, `shell`,
  `script`, `sql`, backticks, `$(`, `${`, `;`, `--`, `/*` — are
  rejected at create/update/test time, not escaped into safety.
- **Complexity bounds (§135).** ≤ 32 conditions, depth ≤ 4,
  sequence ≤ 8 steps, windows 10 s–7 d, threshold counts 2–10000,
  group cardinality ≤ 1000. A rule that would be expensive or
  unbounded cannot exist.
- **Immutability.** Versions are never edited in place; an ACTIVE
  rule returns to TESTING on edit and must be re-promoted, and
  promotion re-compiles the stored version (§111).
- **Evaluation isolation.** Evaluation is a pure function over
  stored events. A failing rule increments its failure counter and
  is surfaced in detection health — it cannot affect other rules
  or the ingestion path.
- **Promotion permissions.** Creating/testing rules and activating
  them are separate permissions (§125), so the author of a rule is
  not automatically its activator in stricter workspaces.
