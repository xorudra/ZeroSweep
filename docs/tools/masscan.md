# Masscan

High-speed port discovery (Prompt 10 §19): elevated policy — explicit profile + administrator approval + hard rate/target clamps; never auto-selected.

- **Slug:** `masscan`
- **Category:** NETWORK
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: IP_ADDRESS, CIDR. Capabilities: HIGH_SPEED_PORT_DISCOVERY. Output format: JSON; parser: masscan-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
