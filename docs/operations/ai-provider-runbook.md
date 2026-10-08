# AI provider runbook (Prompt 36 §119–§124)

## States you will see

- `NOT_CONFIGURED` — no enabled provider+model with the needed
  capability. Expected in the default deployment: add a provider
  (reference name only) and a model under AI settings, or accept the
  labelled RULE_BASED fallback.
- `UNAVAILABLE` — model exists but its provider is disabled.
- Routing rejections are listed per model with reasons (capability,
  residency, classification, policy) — fix the policy or the model
  metadata, never bypass the router.

## Health

Provider health surfaces status only (HEALTHY / DEGRADED /
UNREACHABLE), never credentials. A DEGRADED external provider falls
back per task policy; SECRET-classified tasks never fall back to an
external provider.

## Cost surprises

Check /ai-security (usage & cost panel): if estimatedCostUsd is
null, the providers report no cost metadata — do not estimate by
hand; token totals are exact from request logs.
