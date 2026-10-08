# SearchSploit

Exploit-DB REFERENCE LOOKUP ONLY (Prompt 11 §17): associates known public exploit references with already-identified CVEs/products. It never executes, downloads, compiles or launches exploit code — reference existence is a risk signal, never confirmation of exploitability (§20/§21).

- **Slug:** `searchsploit`
- **Category:** NETWORK
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: IP_ADDRESS. Capabilities: VULNERABILITY_REFERENCE_LOOKUP. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
