# Semgrep

Static analysis with the governed, pinned rule-pack catalog (Prompt 12 §22) — users never supply arbitrary rules.

- **Slug:** `semgrep`
- **Category:** SOURCE_CODE
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1800s.

## Input / Output

Supported targets: SOURCE_REPOSITORY. Capabilities: SAST, CODE_PATTERN_ANALYSIS, SECURITY_RULE_ANALYSIS, DATAFLOW_ANALYSIS. Output format: JSON; parser: semgrep-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
