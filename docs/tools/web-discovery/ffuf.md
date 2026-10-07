# ffuf Adapter

## Purpose
ffuf (fuzz faster u fool): content discovery — directories, files, routes and
optionally virtual hosts — by fuzzing a governed platform wordlist against one
in-scope base URL. It finds routes other discovery methods missed: unlinked
pages, backup files, administrative routes and alternate representations.

## Capabilities
`CONTENT_DISCOVERY`, `DIRECTORY_DISCOVERY`, `FILE_DISCOVERY`, `VHOST_DISCOVERY`

## Supported target types
WEB_APPLICATION

## Risk level
MODERATE (content discovery is intrusive-adjacent: conservative defaults, and
it only runs inside an approved scan against verified, in-scope targets)

## Execution mode
CONTAINER (`ffuf/ffuf` in production; a trusted administrator-installed binary
on PATH is equally supported). Argument array only — no shell, no
user-supplied flags.

## Planned invocation (argument array)
`ffuf -w /wordlists/<registered-list> -u <base-url>FUZZ -of json -o /dev/stdout -s -rate 10 -t 10 -timeout 10`

Vhost mode is a SEPARATE, separately enabled plan: the FUZZ keyword moves
into a `Host: FUZZ.<target-host>` header against the in-scope origin. It is
off by default.

## Required configuration
None beyond pipeline inputs. Declared optional fields: `urls` (pipeline),
`wordlistId` (a REGISTERED wordlist id — never a path), `wordlistProfile`
(SMALL/STANDARD/COMPREHENSIVE, chosen by the worker from the scan profile),
`technologies` (pipeline hints), `rateLimit` (default 10 rps, hard cap 50),
`concurrency` (default 10, hard cap 20), `vhostMode`, `timeoutSeconds`.

Deliberately absent from every plan: `-r` (redirect following — destinations
are recorded, never chased), user-defined match/filter codes (they would
hide real inventory), and recursion flags.

## Output format
JSON document (`-of json`): results with url, status, length, words, lines,
content-type, redirectlocation.

## Normalization behavior
Each result becomes an endpoint with response-classification metadata
(status, length, content type, redirect location) and a response fingerprint
for soft-404/wildcard analysis. Findings are ALWAYS empty: discovery produces
inventory, never vulnerabilities.

## Scope behavior
The plan's base URL comes from persisted in-scope inventory; every result
receives an IN_SCOPE / OUT_OF_SCOPE verdict during processing. Out-of-scope
redirect destinations are recorded on the endpoint, never followed, never
promoted.

## Health
`-V`/PATH probe. Absent binary → UNAVAILABLE, honestly; nothing is faked.

## Limitations
Fixture-verified (recorded output of the controlled test application);
live runs require the tool on the worker host. Response bodies are never
requested for storage and never persisted — metadata only.
