# AI security model (Prompt 36)

## Trust boundaries

The AI layer is the LEAST trusted component in the platform. Models
(external, local or mock) receive only redacted, permission-filtered
context and return text that is treated as untrusted until it
passes grounding, schema and sanitization checks.

## Non-negotiables

1. No execution surface: the AI cannot run scans, commands, SQL,
   cloud/Kubernetes/device operations or exploits — structurally,
   because no such tool exists in the gateway catalog (§26).
2. No authorization power: AI_CANNOT_AUTHORIZE — the copilot cannot
   create/expand authorization, approve actions, grant RBAC or
   verify ownership (established P29 §149, reaffirmed §164).
3. RBAC before retrieval; cross-tenant context impossible by
   construction (workspace-scoped loaders + SDK filter).
4. Redaction before provider: SECRET-classified fields are REMOVED,
   not masked; raw secrets never reach a provider, a trace or a log.
5. Grounding: citations only to in-context records; absent data is
   INSUFFICIENT_EVIDENCE, never invented.
6. Providers are reference names only; transports honestly report
   NOT_CONFIGURED; RULE_BASED fallback is labelled.
7. Budgets, rate limits and loop bounds are enforced in code.
