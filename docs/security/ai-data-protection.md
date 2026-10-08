# AI data protection (Prompt 21 §14/§62–§65, §13)

## Classification gates (§13/§14)

Five tiers: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, SECRET.
Task policy enforces them before any provider call:

- **SECRET** is never sent to an external provider — the policy
  denies the task; SECRET-classified fields are *removed* (not merely
  masked) from context before assembly.
- Any context above a provider's approved classifications is denied.
- LOCAL providers (organization-controlled models, §65) may receive
  CONFIDENTIAL when policy allows; external providers never receive
  RESTRICTED-or-above SECURE_CODE context by default.

## Credential discipline (§64)

Providers store a credential **reference name** only. API responses
expose `credentialConfigured: boolean` — never the reference and
never a value. Secret scanning runs over provider-bound context and
admin payloads (§93 test: a planted bearer token in evidence is
redacted before the provider sees it).

## Retention & logging (§62/§63)

- Conversations are workspace- and user-scoped; retrieval prunes
  conversations older than the workspace `chatRetentionDays`
  (default 30).
- `AiRequestLog` stores counters only (tokens, redactions, injection
  flags, latency, status) — never full prompts or raw responses.
- Stored chat content is the **sanitized** text only (§59).
