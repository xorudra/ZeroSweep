# enum4linux-ng

Governed SMB/LDAP inventory adapter (Prompt 15 §42/§43): users/groups/shares/policy enumeration with bounded flags — the all-in-one mode and RID cycling are refused at plan time.

- **Slug:** `enum4linux-ng`
- **Category:** ACTIVE_DIRECTORY
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: CUSTOM_ALLOWLIST; default timeout: 900s.

## Input / Output

Supported targets: ACTIVE_DIRECTORY_DOMAIN, ACTIVE_DIRECTORY_FOREST, DOMAIN_CONTROLLER, LDAP_DIRECTORY, ACTIVE_DIRECTORY. Capabilities: SMB_DIRECTORY_ENUMERATION, WINDOWS_SERVICE_DISCOVERY, SAFE_SERVICE_ENUMERATION. Output format: JSON; parser: enum4linux-ng-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
