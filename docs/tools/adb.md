# ADB (lab devices)

ADB lab adapter (Prompt 17 §59): governed operations on APPROVED ZeroSweep-managed lab devices only — device inventory, install of the authorized build (hash verified, §60), launch, logs, reset. There is NO generic adb shell endpoint anywhere (§59/§75); personal devices are never targeted (§55).

- **Slug:** `adb`
- **Category:** MOBILE
- **License:** OPEN_SOURCE
- **Risk level:** RESTRICTED
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: MOBILE_APP. Capabilities: DEVICE_MANAGEMENT, APP_INSTALLATION, LOG_COLLECTION, CONTROLLED_APP_INTERACTION. Output format: JSON; parser: adb-lab-session. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
