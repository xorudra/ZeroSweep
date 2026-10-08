# checksec

checksec hardening analysis (Prompt 18 §15): NX/PIE/RELRO/canary/FORTIFY properties of a registered binary artifact, parsed from headers — the artifact is input data, never executed.

- **Slug:** `checksec`
- **Category:** BINARY
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 600s.

## Input / Output

Supported targets: BINARY. Capabilities: BINARY_ANALYSIS, BINARY_HARDENING_ANALYSIS. Output format: JSON; parser: checksec-report. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
