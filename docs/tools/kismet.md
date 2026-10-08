# Kismet

Kismet passive wireless discovery (Prompt 19 §16/§18): listens only — never transmits, associates or probes. Runs on dedicated WIRELESS_PASSIVE_ANALYSIS sensor workers against approved sensors.

- **Slug:** `kismet`
- **Category:** WIRELESS
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: WIRELESS_LAB. Capabilities: PASSIVE_WIFI_DISCOVERY, ACCESS_POINT_INVENTORY, STATION_OBSERVATION, CHANNEL_OBSERVATION, WIRELESS_SECURITY_METADATA. Output format: JSON; parser: kismet-devices. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
