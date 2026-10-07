# WhatWeb Adapter

## Purpose
WhatWeb: web technology fingerprinting (server, CMS, frameworks, languages, JavaScript libraries, analytics) at aggression level 1 — passive fingerprinting of the landing response only; the level is fixed by the adapter and cannot be raised by profiles.

## Capabilities
`TECHNOLOGY_DETECTION`

## Supported target types
WEB_APPLICATION

## Risk level
LOW

## Execution mode
CONTAINER (official/project image in production; a trusted administrator-installed
binary on PATH is equally supported). The adapter builds an argument array only —
no shell strings, no user-supplied flags, no downloads.

## Planned invocation (argument array)
``whatweb --no-errors -a 1 --log-json /dev/stdout <url>``

## Required configuration
None beyond the target. Optional declared fields only: `timeoutSeconds`
(all adapters), `hosts`/`urls` (pipeline-supplied discovery inputs where the
adapter declares them), `depth` (katana, 1–3). Any other key — including
`command`, `shell` or `args` — is rejected by SDK configuration validation.

## Output format
JSON array `[{target, http_status, plugins:{Name:{version[], certainty}}}]` (brief text output also parsed)

## Normalization behavior
Plugins become Technologies with version + confidence (certainty/100, default 0.8) and an inferred category (Web Server / CMS / Language / Framework / JavaScript Library / Analytics / Other). Technology detection never creates findings.
Findings are ALWAYS empty for this adapter: reconnaissance produces
assets/services/technologies/endpoints, never vulnerabilities (Prompt 5 §47).

## Scope behavior
Scope is checked three times: before execution (plan + policy gates), while
processing discovery output (every discovered host/URL gets an IN_SCOPE /
OUT_OF_SCOPE verdict), and again before any downstream stage consumes the
inventory. Out-of-scope discoveries are recorded, never promoted, and never
expand the authorized scope.

## Health
`--version`/PATH probe. When the binary is absent the adapter reports
UNAVAILABLE and orchestration degrades or substitutes — it never fabricates
a run. Exit behaviour is classified SUCCESS / PARTIAL / FAILED / TIMED_OUT /
CANCELLED per §38; malformed output lines become parser warnings.

## Limitations
Fixture-verified in CI (recorded outputs); live runs require the tool to be
installed (container image or trusted binary) on the worker host. Rate and
discovery budgets (Prompt 5 §27–§28) bound every execution.
