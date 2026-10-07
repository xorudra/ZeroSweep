# Arjun Adapter

## Purpose
Arjun: HTTP parameter discovery. Given ONE eligible endpoint, Arjun finds
the parameter names it accepts — the inventory later safe-testing phases
reason about.

## Capabilities
`PARAMETER_DISCOVERY`

## Supported target types
WEB_APPLICATION, API

## Risk level
LOW

## Execution mode
CONTAINER (platform image built from the official release; trusted PATH
binary equally supported). Argument array only.

## Planned invocation (argument array)
`arjun -u <prioritized-endpoint> -oJ /dev/stdout -t 5 --stable`

## Target discipline (§28 — the important part)
Arjun is **never run blindly against every URL in history**. The adapter
prioritizes the endpoints handed down from persisted inventory:
API-looking routes first, then GET endpoints, then live (status < 400)
ones; static resources are excluded and out-of-scope endpoints are never
eligible. Exactly ONE endpoint — the top priority — goes into the plan.
`--stable` keeps request behaviour deliberate; threads are hard-capped
at 10 (default 5), under the strict parameter-discovery budget
(`maxParameterRequests`).

## Required configuration
Declared optional fields only: `urls` (pipeline inventory), `concurrency`
(1–10), `timeoutSeconds`.

## Output format
JSON object mapping each probed URL to its discovered parameter names:
`{"https://…/search": {"params": ["q", "page"]}}`.

## Normalization behavior
Parameter NAMES join `EndpointParameter` inventory with provenance `arjun`
and confidence 0.9, deduplicated against Wfuzz's parameter template with
unioned provenance. Arjun's per-parameter detail values are deliberately
ignored — a parameter VALUE is never read into storage anywhere. The probed
endpoint itself is emitted so provenance attaches to it. Findings are
ALWAYS empty: a parameter existing is not a vulnerability.

## Health
No clean version flag exists; presence is probed on PATH. Absent →
UNAVAILABLE, honestly reported.

## Limitations
Fixture-verified (recorded JSON); live runs require the tool on the worker
host.
