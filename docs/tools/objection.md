# Objection

APPROVAL_REQUIRED registration (Prompt 17 §73/§74): Objection is never an interactive shell into an application. Governed, administrator-approved modules only, inside an approved lab session — no adapter exists by default and arbitrary commands are prohibited (§75).

- **Slug:** `objection`
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
