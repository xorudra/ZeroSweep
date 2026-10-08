# SSTImap

Server-side template injection detection; requires explicit approval.

- **Slug:** `sstimap`
- **Category:** WEB
- **License:** OPEN_SOURCE
- **Risk level:** INTRUSIVE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: WEB_APPLICATION. Capabilities: VULNERABILITY_SCANNING. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
