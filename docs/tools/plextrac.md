# PlexTrac

Commercial reporting platform; admin supplies access.

- **Slug:** `plextrac`
- **Category:** REPORTING
- **License:** ADMIN_PROVIDED — customer/administrator-supplied license required; ZeroSweep never bundles commercial licenses (§122–§126)
- **Risk level:** PASSIVE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Installed and licensed by the customer/administrator in their own environment; ZeroSweep connects through its governed adapter only when configured.

## Worker requirement

Execution mode: ADMIN_PROVIDED; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: WEB_APPLICATION. Capabilities: REPORT_EXPORT. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
