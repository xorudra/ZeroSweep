# Greenbone/OpenVAS

Administrator-managed network vulnerability scanner (Prompt 11 §3): governed scan tasks over scope-derived targets with administrator-approved logical profiles (BASELINE/STANDARD/COMPREHENSIVE); results import through the correlation pipeline.

- **Slug:** `greenbone-openvas`
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

Supported targets: IP_ADDRESS, CIDR. Capabilities: VULNERABILITY_SCANNING, NETWORK_VULNERABILITY_ASSESSMENT, SCAN_RESULT_IMPORT, VULNERABILITY_DETECTION. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
