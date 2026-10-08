# AI provider policy (Prompt 21 §3–§6, §64, §103, §107, §110)

## Provider model (§3/§4)

Providers are typed `OPENAI_COMPATIBLE`, `ANTHROPIC`, `AZURE_OPENAI`,
`LOCAL`, `MOCK`; models register against them with capabilities,
context limits, output limits, allowed tasks and data-residency
metadata. Only the in-process **MOCK** transport is provisioned in
this build (deterministic, offline, contract-faithful). Other types
resolve to an honest NOT_CONFIGURED/PROVIDER_ERROR state — transports
are a provisioning step, never faked (§103).

## Data policy (§64)

Per provider: approved classifications, data residency, region,
encryption posture, retention and training-data policy; the platform
may store prompts/outputs per `storePrompts` / `storeOutputs` flags
(default: counters only). Credentials exist only as references (§110).

## Task policy (§6)

`AITaskPolicy` resolves each task to ALLOW / DENY /
REQUIRE_REDACTION / REQUIRE_REVIEW, strictest-wins across rules:
workspace disabled tasks, SECRET-in-context, external-provider +
RESTRICTED-or-above context, classification above the provider's
approval, MOCK-only operations, source-code/raw-evidence access
policies, and a hard DENY for any execution-shaped request
(§115-style input fails at zod/boundary before policy).

## Failure & fallback (§103/§107)

Provider failure never fails the platform: the task falls back to a
deterministic RULE_BASED answer or reports PROVIDER_ERROR. A fallback
may never downgrade data policy — the fallback provider's policy is
re-evaluated before use, and if the fallback is *less* restrictive
than the primary for the context's classification, the task is denied
rather than rerouted.
