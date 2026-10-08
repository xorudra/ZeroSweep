# pwndbg

APPROVAL_REQUIRED registration (Prompt 18 §65/§66): pwndbg is a governed debug-session descriptor under the same BinaryDebugPolicy as GDB — LAB + authorization + separate approval + isolation + kill switch. No executing adapter exists in this build.

- **Slug:** `pwndbg`
- **Category:** BINARY
- **License:** OPEN_SOURCE
- **Risk level:** RESTRICTED
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: BINARY. Capabilities: BINARY_ANALYSIS, DYNAMIC_DEBUGGING. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
