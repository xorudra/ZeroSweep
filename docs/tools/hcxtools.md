# hcxtools (hcxpcapngtool)

hcxpcapngtool offline capture processing (Prompt 19 §23): approved capture artifacts only; hash-export modes are not expressible and authentication material is counted, never extracted (§67).

- **Slug:** `hcxtools`
- **Category:** WIRELESS
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 600s.

## Input / Output

Supported targets: WIRELESS_LAB. Capabilities: OFFLINE_CAPTURE_PROCESSING, CAPTURE_METADATA_EXTRACTION. Output format: TEXT; parser: hcxpcapngtool-summary. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
