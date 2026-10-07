# Katana Adapter

## Purpose
ProjectDiscovery Katana: scoped web crawling for endpoint inventory. The adapter enforces the conservative configuration of Prompt 5 §14: depth hard-capped at 3 (default 2), field scope locked to the root domain (`-fs rdn`), JavaScript endpoint extraction on, concurrency 10, rate 50/s, 1 MiB response cap, 10 s timeout — and NO form-filling flags ever (`-aff` and friends are absent and rejected in tests).

## Capabilities
`WEB_CRAWLING`, `URL_DISCOVERY`, `ENDPOINT_DISCOVERY`

## Supported target types
WEB_APPLICATION

## Risk level
LOW under the enforced conservative configuration

## Execution mode
CONTAINER (official/project image in production; a trusted administrator-installed
binary on PATH is equally supported). The adapter builds an argument array only —
no shell strings, no user-supplied flags, no downloads.

## Planned invocation (argument array)
``katana -u <url> -jsonl -silent -d <depth> -jc -timeout 10 -c 10 -rl 50 -mrs 1048576 -fs rdn``

## Required configuration
None beyond the target. Optional declared fields only: `timeoutSeconds`
(all adapters), `hosts`/`urls` (pipeline-supplied discovery inputs where the
adapter declares them), `depth` (katana, 1–3). Any other key — including
`command`, `shell` or `args` — is rejected by SDK configuration validation.

## Output format
JSONL `{request:{method, endpoint}, response:{status_code}}`

## Normalization behavior
Endpoints normalize to method + canonical URL + status + parameter names, provenance `katana`. Out-of-scope crawl results are recorded as OUT_OF_SCOPE references only.
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
