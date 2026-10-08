# Insomnia

API client — workspace exports import as guarded inventory (Prompt 9 §12), secret environment values dropped.

- **Slug:** `insomnia`
- **Category:** API
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: NONE; default timeout: 60s.

## Input / Output

Supported targets: API. Capabilities: API_DISCOVERY, SPEC_IMPORT. Output format: JSON; parser: insomnia-export. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
