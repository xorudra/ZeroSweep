# Cutter

ANALYST_TOOL registration (Prompt 18 §35): Cutter is an analyst-workstation GUI for radare2 — it is registered for inventory/health only and NEVER executes in the ZeroSweep pipeline.

- **Slug:** `cutter`
- **Category:** BINARY
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: BINARY. Capabilities: BINARY_ANALYSIS, STATIC_BINARY_ANALYSIS. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
