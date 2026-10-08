# ldapsearch

Governed LDAP query adapter (Prompt 15 §14/§41): platform-generated typed queries only (fixed filters + attribute sets), LDAPS preferred, paged and size-bounded. Raw filters, arbitrary base DNs and credential values in configuration are refused.

- **Slug:** `ldapsearch`
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

Supported targets: ACTIVE_DIRECTORY_DOMAIN, ACTIVE_DIRECTORY_FOREST, DOMAIN_CONTROLLER, LDAP_DIRECTORY, ACTIVE_DIRECTORY. Capabilities: DIRECTORY_INVENTORY, LDAP_SECURITY_ANALYSIS. Output format: LDIF; parser: ldapsearch-ldif. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
