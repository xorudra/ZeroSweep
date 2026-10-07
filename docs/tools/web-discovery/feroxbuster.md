# Feroxbuster Adapter

## Purpose
Feroxbuster: recursive content discovery. Where ffuf sweeps one level with a
wordlist, Feroxbuster follows discovered directories deeper — bounded hard
by the adapter so recursion can never explode the request budget.

## Capabilities
`CONTENT_DISCOVERY`, `DIRECTORY_DISCOVERY`, `RECURSIVE_CONTENT_DISCOVERY`

## Supported target types
WEB_APPLICATION

## Risk level
MODERATE (recursive requests multiply fast — hence the hard caps below)

## Execution mode
CONTAINER (`epi052/feroxbuster` in production; trusted PATH binary equally
supported). Argument array only.

## Planned invocation (argument array)
`feroxbuster -u <base-url> -w /wordlists/<registered-list> --json --output /dev/stdout --silent --depth 2 --threads 10 --rate-limit 10 --timeout 10`

## Guardrails (hard caps, enforced in adapter code)
- Recursion depth: default 2, **hard maximum 4** — schema validation refuses
  anything higher, and the plan clamps regardless.
- Rate limit: default 10 rps, hard cap 50. Concurrency: default 10, cap 20.
- No `--extract-links` (no body-driven crawling beyond the wordlist plan)
  and no redirect following: scope stays exactly where the plan put it.

## Required configuration
Declared optional fields only: `urls`, `wordlistId` (registered id, never a
path), `wordlistProfile` (this adapter defaults to STANDARD — recursion with
the small list is rarely useful — selected by the worker from the profile),
`technologies`, `rateLimit`, `concurrency`, `depth` (1–4), `timeoutSeconds`.

## Output format
JSONL stream: `{"type":"response", url, status, content_length, line_count,
word_count}` records interleaved with statistics/log records (ignored).

## Normalization behavior
Response records become endpoints with classification metadata and response
fingerprints. Non-response records never become inventory. Findings are
ALWAYS empty.

## Scope behavior
Same triple-check as every adapter: plan/policy gates before execution,
per-URL verdicts during processing, and downstream stages consume only
in-scope inventory.

## Health
`--version`/PATH probe; absent → UNAVAILABLE, honestly reported.

## Limitations
Fixture-verified (recorded JSONL); live runs require the binary on the
worker host. If Feroxbuster fails mid-stage, the stage degrades to PARTIAL
and the other tools' results still land (Prompt 6 §60).
