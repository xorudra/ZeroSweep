# Nessus Professional

Commercial vulnerability scanner (Prompt 11 §10) — COMMERCIAL / ADMIN_PROVIDED / LICENSE_REQUIRED: used only against an administrator-provided licensed environment, never redistributed. Unconfigured it reports NOT_CONFIGURED (§85).

- **Slug:** `nessus-professional`
- **Category:** NETWORK
- **License:** ADMIN_PROVIDED — customer/administrator-supplied license required; ZeroSweep never bundles commercial licenses (§122–§126)
- **Risk level:** MODERATE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Installed and licensed by the customer/administrator in their own environment; ZeroSweep connects through its governed adapter only when configured.

## Worker requirement

Execution mode: ADMIN_PROVIDED; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: IP_ADDRESS, CIDR. Capabilities: VULNERABILITY_SCANNING, NETWORK_VULNERABILITY_ASSESSMENT, SCAN_RESULT_IMPORT, VULNERABILITY_DETECTION. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
