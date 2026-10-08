# ROADtools

ROADtools (Entra ID) DEFENSIVE analysis (Prompt 14 §29): role assignments and application permissions from recorded exports. Offensive directory operations are never invoked.

- **Slug:** `roadtools`
- **Category:** CLOUD
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: AZURE. Capabilities: DIRECTORY_ANALYSIS, IDENTITY_INVENTORY. Output format: JSON; parser: roadtools-import. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
