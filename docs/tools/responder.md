# Responder

DISABLED by policy (Prompt 15 §54/§120): Responder poisons LLMNR/NBT-NS/mDNS and captures credentials. Poisoning and credential capture are permanently excluded — no adapter exists.

- **Slug:** `responder`
- **Category:** ACTIVE_DIRECTORY
- **License:** OPEN_SOURCE
- **Risk level:** RESTRICTED
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: ACTIVE_DIRECTORY. Capabilities: NETWORK_POISONING, CREDENTIAL_CAPTURE. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
