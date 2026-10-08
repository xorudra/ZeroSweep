# Mock Security Adapter (TEST ONLY)

Exercises the pipeline end-to-end. Performs no network activity and produces no findings.

- **Slug:** `mock`
- **Category:** REPORTING
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: MOCK; network policy: NO_NETWORK; default timeout: 5s.

## Input / Output

Supported targets: DOMAIN, WEB_APPLICATION. Capabilities: —. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
