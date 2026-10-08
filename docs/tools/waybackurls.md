# waybackurls

Fetches archived URLs from the Wayback Machine.

- **Slug:** `waybackurls`
- **Category:** RECON
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: INTERNET_READ_ONLY; default timeout: 300s.

## Input / Output

Supported targets: DOMAIN. Capabilities: URL_DISCOVERY, HISTORICAL_URL_DISCOVERY. Output format: TEXT; parser: waybackurls-text. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
