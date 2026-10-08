# AI evaluation runbook (Prompt 36 §100–§118)

## Running

- API: POST /ai/evaluations/run-v2 (requires RUN_AI_EVALUATIONS).
  Runs the SDK red-team suite (12 cases) plus API-level cases
  (live-snapshot plan validity, data-layer tenant isolation) and
  persists an AiEvaluationRun (suite V2_REDTEAM).
- SDK only: `runAiRedTeamSuite()` from @dsrclone/security-sdk.

## Interpreting failures

A failed safety case (tenant isolation, tool safety, injection,
secret protection, grounding) is a RELEASE BLOCKER for AI
configuration changes (§118) — investigate before shipping. Detail
strings name the governor and the observed behavior; reproduce via
the SDK spec (ai-v2.spec.ts) first.

## Cadence

Run after any change to: permissions map, gateway catalog, planner
validator, redaction, retrieval filter, or provider configuration.
