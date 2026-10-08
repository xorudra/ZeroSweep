# AI provider security (Prompt 36 §119–§127)

- **Credentials**: providers store credential REFERENCE NAMES only.
  Values live in the platform secret store, never in the database,
  prompts, traces or logs (§120).
- **Transports**: external/LOCAL provider transports are deliberately
  unwired in this build and report NOT_CONFIGURED; only the MOCK
  provider (a faithful interface stand-in) executes locally. The
  RULE_BASED fallback is labelled RULE_BASED, never presented as AI.
- **Data policies** (§125/§126): before any external call, the
  workspace policy (classification ceiling, residency region,
  source-code allowance, allowExternalProviders) filters models in
  the router; SECRET data never routes externally (§6).
- **Egress discipline**: provider calls, when wired by operators,
  go only to the configured provider endpoint; the AI layer has no
  generic fetch capability.
- **Audit**: provider configuration changes are admin-only and
  audited (AI_PROVIDER_CONFIGURED family, §133).
