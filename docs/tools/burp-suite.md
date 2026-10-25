# Burp Suite (mobile proxy)

Burp Suite connector for mobile proxy analysis (Prompt 17 §65): reuses the Prompt 8 governed connector + MOBILE_PROXY_ANALYSIS — sanitized flow metadata for authorized lab traffic only; no unrestricted Burp control exists.

- **Slug:** `burp-suite`
- **Category:** MOBILE
- **License:** ADMIN_PROVIDED — customer/administrator-supplied license required; ZeroSweep never bundles commercial licenses (§122–§126)
- **Risk level:** MODERATE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Installed and licensed by the customer/administrator in their own environment; ZeroSweep connects through its governed adapter only when configured.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: MOBILE_APP. Capabilities: MOBILE_PROXY_ANALYSIS. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
