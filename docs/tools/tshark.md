# tshark

Offline capture analysis (Prompt 10 §45): protocol hierarchy + HTTP transaction inventory from authorized capture artifacts.

- **Slug:** `tshark`
- **Category:** NETWORK
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NONE; default timeout: 600s.

## Input / Output

Supported targets: CIDR, IP_ADDRESS. Capabilities: PACKET_ANALYSIS. Output format: JSON; parser: tshark-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
