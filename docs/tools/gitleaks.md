# Gitleaks

Secret scanning for git repositories (Prompt 12 §34). Values are fingerprinted at parse time — never stored or displayed.

- **Slug:** `gitleaks`
- **Category:** SOURCE_CODE
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: SOURCE_REPOSITORY. Capabilities: SECRET_SCANNING, SECRET_DETECTION. Output format: JSON; parser: gitleaks-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
