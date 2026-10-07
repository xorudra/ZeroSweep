# Subfinder Adapter

## Purpose
Passive subdomain enumeration from public sources (certificate transparency, search APIs, DNS datasets) via ProjectDiscovery Subfinder.

## Capabilities
`SUBDOMAIN_DISCOVERY`

## Supported target types
DOMAIN

## Risk level
LOW (Prompt 5 §5)

## Execution mode
CONTAINER (official/project image in production; a trusted administrator-installed
binary on PATH is equally supported). The adapter builds an argument array only —
no shell strings, no user-supplied flags, no downloads.

## Planned invocation (argument array)
``subfinder -d <domain> -json -silent``

## Required configuration
None beyond the target. Optional declared fields only: `timeoutSeconds`
(all adapters), `hosts`/`urls` (pipeline-supplied discovery inputs where the
adapter declares them), `depth` (katana, 1–3). Any other key — including
`command`, `shell` or `args` — is rejected by SDK configuration validation.

## Output format
JSONL: `{host, input, source}` per line

## Normalization behavior
Each host is canonicalized (lowercase, trailing dot stripped, IDN→punycode) and recorded with provenance `subfinder`. Malformed lines become parser warnings, never failures.
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
