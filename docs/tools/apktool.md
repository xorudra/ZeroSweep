# apktool

apktool resource + manifest analysis (Prompt 17 §18): decodes resources/AndroidManifest.xml in the safe extraction workspace; archive attacks are refused at intake (§107).

- **Slug:** `apktool`
- **Category:** MOBILE
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1200s.

## Input / Output

Supported targets: MOBILE_APP. Capabilities: APK_RESOURCE_ANALYSIS, MANIFEST_EXTRACTION, RESOURCE_EXTRACTION. Output format: JSON; parser: apktool-output. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
