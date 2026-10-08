# hcxdumptool

DISABLED descriptor (Prompt 19 §22/§64): active capture tooling — no executing adapter exists outside explicitly controlled lab workflows; never used against surrounding networks.

- **Slug:** `hcxdumptool`
- **Category:** WIRELESS
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: WIRELESS_LAB. Capabilities: ACTIVE_WIRELESS_CAPTURE. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
