# API Operation Policy (Prompt 9 §16–§17)

Every API operation — imported from a specification, discovered in
traffic, or produced by a tool — is classified before any automation
may touch it. The classifier is `ApiOperationPolicyEngine` in
`packages/security-sdk/src/api/policy.ts`. Classification can only be
**tightened** by administrator overrides, never loosened.

## Classification

| Class | Meaning | Automation |
|---|---|---|
| `SAFE` | Read-only, idempotent (GET / HEAD / OPTIONS on ordinary routes) | May execute in `SAFE_SCHEMA_TESTING` |
| `STATE_CHANGING` | POST / PUT / PATCH and other writes | **Never** in the baseline; excluded by operation name |
| `DESTRUCTIVE_UNKNOWN` | DELETE, unknown verbs, writes whose effect is unclear | **Never** automated in this phase |
| `REVIEW_REQUIRED` | Upload, financial, authentication and similarly sensitive route shapes | Human review only; also blocked from automation |

Rules, in evaluation order:

1. Administrator overrides (tighten-only).
2. Destructive shapes: `DELETE` → `DESTRUCTIVE_UNKNOWN`.
3. HTTP method: GET/HEAD/OPTIONS → `SAFE` candidate; POST/PUT/PATCH →
   `STATE_CHANGING`; anything else → `DESTRUCTIVE_UNKNOWN`.
4. Sensitive route patterns (upload, payment/financial,
   authentication/session routes) escalate a `SAFE` candidate to
   `REVIEW_REQUIRED`.
5. A request body on an otherwise-safe verb escalates scrutiny.

GraphQL follows the same posture: queries may be inventoried and
analysed; **mutations are not executed by default** and subscriptions
are inventory-only (`graphqlOperationAutomatable`).

## Enforcement points

- **Schemathesis planning**: the adapter partitions the imported
  operations with the engine. Non-SAFE operations with known
  operationIds are excluded via `--exclude-name`; `--include-method`
  is pinned to `GET,HEAD,OPTIONS`; the stateful phase is never
  enabled. The `allowStateChanging` configuration key exists for a
  future approved profile — **the worker never sets it**, so the
  baseline cannot execute a state-changing operation even if a
  specification begs for one. Blocked operations are counted and
  emitted as `api.operation_blocked` events.
- **Worker derivation**: schema locations and operation lists reach
  adapters only from the guarded import store via trusted stage
  inputs — never from queue payloads or client input.
- **API surface**: there is no endpoint that executes an API
  operation. Imports, inspection and inventory reads only.

## What this policy forbids (by design)

- Credential attacks and JWT cracking — JWT work is decode-and-observe
  inspection only (§23–§25).
- Mass-assignment exploitation and authorization-bypass exploitation —
  BOLA/authorization checks exist as reviewed test-case *designs*
  (§42); execution belongs to the controlled-validation phase behind
  separate approval.
- Destructive mutations of any kind in automated profiles.

Tests proving exclusion live in
`packages/security-sdk/src/api/policy.spec.ts` (§75),
`packages/security-sdk/src/api/adapters-api.spec.ts` (plan shapes) and
`apps/worker/src/api.e2e.spec.ts` (the recorded Schemathesis
invocation carries exclusions, never state-changing work).
