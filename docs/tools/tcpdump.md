# tcpdump

Bounded packet capture for approved controlled test environments only (Prompt 10 §44): explicit interface, bounded duration/size.

- **Slug:** `tcpdump`
- **Category:** NETWORK
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 300s.

## Input / Output

Supported targets: CIDR, IP_ADDRESS. Capabilities: PACKET_CAPTURE. Output format: TEXT; parser: tcpdump-capture. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
