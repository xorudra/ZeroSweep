# LDAP Directory Connector

Platform read-only directory connector (Prompt 15 §15): LDAPS-preferred typed queries against APPROVED domain controllers only, plus governed import of directory exports. Unconfigured it reports NOT_CONFIGURED — data is never fabricated.

- **Slug:** `ldap-directory-connector`
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

Supported targets: ACTIVE_DIRECTORY_DOMAIN, ACTIVE_DIRECTORY_FOREST, DOMAIN_CONTROLLER, LDAP_DIRECTORY, ACTIVE_DIRECTORY. Capabilities: DIRECTORY_INVENTORY, LDAP_SECURITY_ANALYSIS, IDENTITY_RELATIONSHIP_DISCOVERY, MANUAL_DIRECTORY_ANALYSIS. Output format: JSON; parser: directory-inventory. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
