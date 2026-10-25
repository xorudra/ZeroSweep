# Frida

DISABLED registration (Prompt 17 §69–§71): Frida instrumentation exists in ZeroSweep only as administrator-reviewed, versioned modules under the MobileInstrumentationPolicy — default DISABLED for static profiles. No adapter exists, arbitrary user-supplied JavaScript is never accepted (§72/§75), and no stage can select it.

- **Slug:** `frida`
- **Category:** MOBILE
- **License:** OPEN_SOURCE
- **Risk level:** RESTRICTED
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: MOBILE_APP. Capabilities: DYNAMIC_INSTRUMENTATION. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
