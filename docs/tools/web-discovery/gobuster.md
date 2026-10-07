# Gobuster Adapter

## Purpose
Gobuster: directory and file discovery with a governed platform wordlist —
a second, independent content-discovery engine whose results corroborate
ffuf/Feroxbuster through endpoint provenance.

## Capabilities
`CONTENT_DISCOVERY`, `DIRECTORY_DISCOVERY`, `FILE_DISCOVERY`

## Supported target types
WEB_APPLICATION

## Risk level
MODERATE

## Execution mode
CONTAINER (platform image built from the official release; trusted PATH
binary equally supported). Argument array only.

## IMPORTANT — dir mode only
This adapter exposes **Gobuster's `dir` mode exclusively** — the explicitly
approved mode for this phase. The `dns`, `vhost`, `s3`, `gcs` and `fuzz`
modes do not exist in this adapter: there is no configuration key that can
select them, and DNS discovery belongs to the recon pipeline (dnsx), which
carries its own scope discipline. Tests assert the planned mode list.

## Planned invocation (argument array)
`gobuster dir -u <base-url> -w /wordlists/<registered-list> -q -t 10 --delay 100ms --timeout 10s`

No `-r`: redirects are recorded by the parser, never followed.

## Required configuration
Declared optional fields only: `urls`, `wordlistId` (registered id, never a
path), `wordlistProfile`, `technologies`, `concurrency` (default 10, cap
20), `timeoutSeconds`.

## Output format
Text lines: `/path (Status: 200) [Size: 1234]` with optional
`[--> https://…]` redirect annotations. Gobuster reports PATHS — the parser
absolutizes them against the plan's validated base URL, never against
anything the tool printed.

## Normalization behavior
Endpoints with status, size and redirect location; provenance `gobuster`.
Banner/progress lines are ignored; unrecognized content lines become parser
warnings, never crashes. Findings are ALWAYS empty.

## Scope behavior
Per-URL verdicts at processing; out-of-scope results recorded only.

## Health
`version`/PATH probe; absent → UNAVAILABLE, honestly reported.

## Limitations
Fixture-verified (recorded text output); live runs require the binary on
the worker host.
