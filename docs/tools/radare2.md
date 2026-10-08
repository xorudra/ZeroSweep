# radare2

Radare2 static binary analysis (Prompt 18 §33/§34): typed analysis profiles ONLY — the command line is composed by the adapter from the approved operation set; unrestricted r2 commands via the API are rejected and never planned.

- **Slug:** `radare2`
- **Category:** BINARY
- **License:** OPEN_SOURCE
- **Risk level:** RESTRICTED
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1200s.

## Input / Output

Supported targets: BINARY. Capabilities: BINARY_ANALYSIS, STATIC_BINARY_ANALYSIS, DISASSEMBLY, FUNCTION_INVENTORY, IMPORT_EXPORT_ANALYSIS, STRING_ANALYSIS. Output format: JSON; parser: radare2-report. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
