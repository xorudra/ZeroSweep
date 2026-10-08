# Aircrack-ng (metadata only)

Aircrack-ng restricted by AircrackPolicy (Prompt 19 §19/§20): capture inspection + metadata extraction ONLY — cracking, key recovery and deauthentication modes are not expressible in any plan.

- **Slug:** `aircrack-ng`
- **Category:** WIRELESS
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 600s.

## Input / Output

Supported targets: WIRELESS_LAB. Capabilities: CAPTURE_METADATA_ANALYSIS, WIRELESS_CONFIGURATION_ANALYSIS, OFFLINE_CAPTURE_INSPECTION. Output format: TEXT; parser: aircrack-capture-info. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
