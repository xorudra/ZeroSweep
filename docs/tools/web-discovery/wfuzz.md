# Wfuzz Adapter — controlled mode only

## Purpose
Wfuzz is a general-purpose fuzzer, and general-purpose fuzzing is exactly
what this platform does NOT expose. The adapter runs Wfuzz in CONTROLLED
mode: only two predefined platform templates exist, and arbitrary payload
construction is impossible through it.

## Capabilities
`CONTENT_DISCOVERY`, `PARAMETER_DISCOVERY`

## Supported target types
WEB_APPLICATION

## Risk level
MODERATE

## The two templates (the entire configuration surface)
1. **CONTENT** — the registered directory wordlist is fuzzed into the URL
   path of one in-scope endpoint: `wfuzz -z file,<list> --hc 404 -t 5 -f /dev/stdout,json <base>FUZZ`
2. **PARAMETER** — the registered PARAMETER_NAMES list is fuzzed as query
   keys against one eligible endpoint with a fixed benign marker value:
   `wfuzz -z file,<parameter-names> --hc 404,400 -t 5 -f /dev/stdout,json <base>?FUZZ=zerosweep`

The worker selects the template from the STAGE (parameter-discovery stage →
PARAMETER, otherwise CONTENT) — users never choose payloads, and there is
no `payload`, `wordlist-path` or free-form argument field anywhere in the
adapter's schema. Validation tests prove unknown keys and template values
other than CONTENT/PARAMETER are rejected.

Explicitly out of scope for this adapter (later phases, with their own
guardrails): authentication attacks, injection testing, encoding attacks,
blind exploitation.

## Output format
JSON result list: fuzzed url, `code`, lines/words/chars, payload
(`description` in older versions).

## Normalization behavior
Path-fuzzing entries become endpoints. For the PARAMETER template, the
fuzzed query KEYS become parameter records (name + QUERY location) on the
base endpoint — deduplicated against Arjun's results with unioned
provenance. Fuzzed VALUES are never stored. Findings are ALWAYS empty.

## Scope behavior
Plans are built only from persisted in-scope inventory; per-URL verdicts at
processing; out-of-scope results recorded only.

## Health
`--version`/PATH probe; absent → UNAVAILABLE, honestly reported.

## Limitations
Fixture-verified (recorded JSON for both templates); live runs require the
binary on the worker host. Threads hard-capped at 10.
