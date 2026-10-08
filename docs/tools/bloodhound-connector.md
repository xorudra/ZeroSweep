# BloodHound Import Connector

BloodHound/SharpHound dataset IMPORT connector (Prompt 15 §27–§31): parses recorded collector exports into the evidence-backed identity graph. Credential material in exports is stripped before persistence (§113); session/local-admin edges follow the collection policy (§29).

- **Slug:** `bloodhound-connector`
- **Category:** ACTIVE_DIRECTORY
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: ACTIVE_DIRECTORY_DOMAIN, ACTIVE_DIRECTORY_FOREST, DOMAIN_CONTROLLER, LDAP_DIRECTORY, ACTIVE_DIRECTORY. Capabilities: DIRECTORY_RELATIONSHIP_COLLECTION, IDENTITY_GRAPH, SNAPSHOT_IMPORT. Output format: JSON; parser: bloodhound-import. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
