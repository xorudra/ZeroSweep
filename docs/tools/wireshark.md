# Wireshark

ANALYST_TOOL registration (Prompt 19 §25): Wireshark is analyst-workstation GUI tooling — registered for inventory/health only; backend automation uses tshark and Wireshark NEVER executes in the pipeline.

- **Slug:** `wireshark`
- **Category:** WIRELESS
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: WIRELESS_LAB. Capabilities: PCAP_ANALYSIS, FRAME_ANALYSIS_80211. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
