# SharpHound

BloodHound data collector for authorized AD environments (Prompt 15 §27). Collection methods are policy-classified: SAFE methods run by default; session/local-group methods need recorded approval; everything else is refused (§29).

- **Slug:** `sharphound`
- **Category:** ACTIVE_DIRECTORY
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: CUSTOM_ALLOWLIST; default timeout: 3600s.

## Input / Output

Supported targets: ACTIVE_DIRECTORY_DOMAIN, ACTIVE_DIRECTORY_FOREST, DOMAIN_CONTROLLER, LDAP_DIRECTORY, ACTIVE_DIRECTORY. Capabilities: DIRECTORY_RELATIONSHIP_COLLECTION, IDENTITY_RELATIONSHIP_DISCOVERY. Output format: JSON; parser: bloodhound-import. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
