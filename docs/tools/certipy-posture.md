# Certipy (posture, find-only)

Governed Certipy FIND-only posture adapter (Prompt 15 §48–§50): inventories CAs and templates and classifies ESC1–ESC8-style configuration risk. Every other Certipy action is refused at plan time (§112).

- **Slug:** `certipy-posture`
- **Category:** ACTIVE_DIRECTORY
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: ACTIVE_DIRECTORY_DOMAIN, ACTIVE_DIRECTORY_FOREST, DOMAIN_CONTROLLER, LDAP_DIRECTORY, ACTIVE_DIRECTORY. Capabilities: ADCS_INVENTORY, ADCS_POSTURE_ANALYSIS. Output format: JSON; parser: certipy-find. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
