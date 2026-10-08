# Netdiscover

ARP-based local network host discovery (Prompt 10 §21) — approved internal workers with layer-2 access only.

- **Slug:** `netdiscover`
- **Category:** NETWORK
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 300s.

## Input / Output

Supported targets: CIDR. Capabilities: LOCAL_NETWORK_DISCOVERY. Output format: TEXT; parser: netdiscover-text. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
