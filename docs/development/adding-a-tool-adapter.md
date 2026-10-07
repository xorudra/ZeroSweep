# Adding a Tool Adapter

Adapters are trusted code installed by administrators/developers at deploy
time. Users can never upload or register an adapter at runtime.

1. **Add catalog metadata** — one row in `packages/database/prisma/seed.ts`
   (slug, name, primary category, risk level, license type, capabilities,
   supported target types, credential *reference* names, one-line
   description). Multi-category tools keep a single entry.
2. **Implement the adapter** in the worker's adapter package (later phases):
   extend `BaseSecurityToolAdapter`, declare full `ToolMetadata` including a
   structured `inputSchema` (never a `command` field), and implement
   `buildExecutionPlan` returning an executable + argument array — build
   arguments from validated values only, never string concatenation.
3. **Declare the container contract** — image + digest, `networkPolicy`,
   timeouts and resource limits at or below administrator maximums
   (`clampTimeout`, `clampRateLimits`).
4. **Write a parser** implementing `SecurityToolParser` (or reuse JSON/JSONL/
   XML) that emits `NormalizedSecurityResult`; compute `sourceFingerprint`
   for every finding; never invent CVE/CWE/CVSS values.
5. **Register it** in the worker's `ToolRegistry` bootstrap. Registration
   fails on duplicate slug/id or invalid metadata — fix the metadata, don't
   bypass validation.
6. **Test** — metadata validation, target compatibility, scope/policy
   behaviour for your risk level, parser fixtures (including malformed
   output → `ParserError`), and the security cases: shell metacharacters in
   any input must be rejected, never executed.
7. **Seed the adapter row as disabled** until the implementation is
   reviewed; enabling is an administrator action, and INTRUSIVE/RESTRICTED
   adapters additionally require the approval workflow.
