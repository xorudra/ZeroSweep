# AI Security Copilot V2 — architecture (Prompt 36)

V2 deepens the Prompt 21 copilot on the SAME architecture: NestJS
module `apps/api/src/modules/ai-security`, pure governors in
`packages/security-sdk/src/ai`, Prisma models in the shared schema.
Nothing about V1's guarantees is relaxed.

## Request path

1. **RBAC before retrieval** (§116): every endpoint checks an AI
   permission before any record is loaded.
2. **Model router** (§5): deterministic selection by task type,
   capability, classification ceiling, provider/workspace residency
   and workspace policy. No capable model ⇒ `NOT_CONFIGURED`, never a
   silent downgrade.
3. **Permission-aware retrieval** (§10–§13): workspace-scoped
   loaders → SDK filter (source permission, classification ceiling,
   resource ACLs). Skipped sources are disclosed (§21).
4. **Context construction** (§14–§22): labelled sections, untrusted
   records wrapped as data, redaction BEFORE any provider call
   (SECRET fields removed, not masked).
5. **Tool gateway** (§27–§35): the only way AI components touch
   platform functions — a closed catalog of typed READ / ANALYZE /
   PLAN / SAFE_ACTION / RESTRICTED_ACTION tools.
6. **Planner + approvals** (§41–§50): deterministic plan validation
   against an immutable authorization snapshot; human approval with
   separation of duties and expiry; execution hands steps to
   governed platform workflows.
7. **Agents** (§51–§57): bounded orchestrated pipelines (allowlist,
   max steps/tokens/tool calls/duration, loop detection §58).
8. **Structured output + grounding** (§65–§70): schema validation,
   claim-level citations (OBSERVED / INFERRED / RECOMMENDED),
   stored Risk Engine V3 output is never recomputed by the AI.
9. **Logging, traces, audit** (§128–§133): sanitized traces (no
   prompts, responses, tool arguments or secrets), append-only audit.

## The invariant

`executed: false` on every AI response. The copilot analyzes,
explains, summarizes and drafts. It cannot authorize, approve,
expand scope, run scans, or call any tool outside the gateway
catalog. Providers are reference names only; unconfigured
transports report NOT_CONFIGURED honestly and the RULE_BASED
fallback is labelled as such.
