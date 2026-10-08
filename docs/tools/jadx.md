# JADX

JADX Android decompilation (Prompt 17 §19): runs in the static sandbox on MOBILE_STATIC_ANALYSIS workers; output is an analysis artifact — decompiled code is NEVER executed and its access is RBAC-gated (§24).

- **Slug:** `jadx`
- **Category:** MOBILE
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1800s.

## Input / Output

Supported targets: MOBILE_APP. Capabilities: ANDROID_DECOMPILATION, STATIC_CODE_EXTRACTION. Output format: JSON; parser: jadx-output. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
