# PingCastle

Active Directory security posture assessment (Prompt 15 §38–§40): healthcheck mode only. The PingCastle score is preserved as a separate metric and mapped findings deduplicate against native checks (§39/§61).

- **Slug:** `pingcastle`
- **Category:** ACTIVE_DIRECTORY
- **License:** ADMIN_PROVIDED — customer/administrator-supplied license required; ZeroSweep never bundles commercial licenses (§122–§126)
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Installed and licensed by the customer/administrator in their own environment; ZeroSweep connects through its governed adapter only when configured.

## Worker requirement

Execution mode: CONTAINER; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: ACTIVE_DIRECTORY_DOMAIN, ACTIVE_DIRECTORY_FOREST, DOMAIN_CONTROLLER, LDAP_DIRECTORY, ACTIVE_DIRECTORY. Capabilities: AD_SECURITY_POSTURE, AD_RISK_ASSESSMENT, DOMAIN_CONFIGURATION_REVIEW. Output format: XML; parser: pingcastle-xml. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
