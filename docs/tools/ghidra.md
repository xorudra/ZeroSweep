# Ghidra

Ghidra headless static analysis (Prompt 17 §34–§36, EXTENDED by Prompt 18 §18–§21): native-library hardening inventory PLUS the binary function/import/export/string inventory, from administrator-approved scripts only. Binaries are never executed; no arbitrary Ghidra script is expressible.

- **Slug:** `ghidra`
- **Category:** BINARY
- **License:** OPEN_SOURCE
- **Risk level:** RESTRICTED
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1800s.

## Input / Output

Supported targets: BINARY, MOBILE_APP. Capabilities: BINARY_ANALYSIS, BINARY_STATIC_ANALYSIS, NATIVE_LIBRARY_ANALYSIS, DISASSEMBLY, DECOMPILATION, FUNCTION_ANALYSIS, IMPORT_EXPORT_ANALYSIS, STRING_REFERENCE_ANALYSIS. Output format: JSON; parser: ghidra-report. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
