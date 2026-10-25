# Pacu

DISABLED by policy (Prompt 14 §34): Pacu is offensive cloud exploitation tooling. ZeroSweep performs read-only assessment only — no adapter exists, it is never enabled and no stage can select it.

- **Slug:** `pacu`
- **Category:** CLOUD
- **License:** OPEN_SOURCE
- **Risk level:** INTRUSIVE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: AWS. Capabilities: CLOUD_OFFENSIVE_TESTING. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
