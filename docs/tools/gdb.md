# GDB

DISABLED outside LAB registration (Prompt 18 §65/§66): GDB exists in DSRclone only as a governed debug-session descriptor — typed approved operations inside an approved, isolated, kill-switched LAB session. No executing adapter exists in this build; unrestricted GDB/Python is never accepted (§68/§93).

- **Slug:** `gdb`
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
