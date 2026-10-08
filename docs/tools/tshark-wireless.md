# tshark (wireless)

tshark offline 802.11 frame analysis (Prompt 19 §24): a FIXED platform field set over approved captures — arbitrary display filters are not expressible (§78).

- **Slug:** `tshark-wireless`
- **Category:** WIRELESS
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: WIRELESS_LAB. Capabilities: PCAP_ANALYSIS, FRAME_ANALYSIS_80211, WIRELESS_PROTOCOL_METADATA. Output format: TEXT; parser: tshark-wireless-fields. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
