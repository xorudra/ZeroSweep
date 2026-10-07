# httpx Adapter

## Purpose
ProjectDiscovery httpx: HTTP probing of resolved, in-scope hosts — status code, title, content type, server header, detected technologies, TLS presence and redirect location.

## Capabilities
`HTTP_PROBING`, `TECHNOLOGY_DETECTION`

## Supported target types
DOMAIN, WEB_APPLICATION, IP_ADDRESS

## Risk level
LOW

## Execution mode
CONTAINER (official/project image in production; a trusted administrator-installed
binary on PATH is equally supported). The adapter builds an argument array only —
no shell strings, no user-supplied flags, no downloads.

## Planned invocation (argument array)
``httpx -json -silent -title -status-code -content-type -web-server -tech-detect -tls-grab -timeout 10 -threads 25 -rate-limit 50` with hosts on stdin`

## Required configuration
None beyond the target. Optional declared fields only: `timeoutSeconds`
(all adapters), `hosts`/`urls` (pipeline-supplied discovery inputs where the
adapter declares them), `depth` (katana, 1–3). Any other key — including
`command`, `shell` or `args` — is rejected by SDK configuration validation.

## Output format
JSONL `{url, host, port, scheme, status_code, title, content_type, webserver, tech[], a[], location}`

## Normalization behavior
Each probe becomes a Service (host/port/scheme/status/title/server) plus technologies; 404/403/500 are recorded as metadata, NEVER as findings. No redirect-following flags are planned: a redirect to another host is stored on the service and surfaces as an OUT_OF_SCOPE reference endpoint — third parties are never chased.
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
