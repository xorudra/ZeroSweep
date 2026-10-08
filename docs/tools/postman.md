# Postman

API platform — collections import as guarded inventory (Prompt 9 §10/§11): secret-like variable values are dropped and replaced by secret references, never stored.

- **Slug:** `postman`
- **Category:** API
- **License:** COMMERCIAL — customer/administrator-supplied license required; DSRclone never bundles commercial licenses (§122–§126)
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Installed and licensed by the customer/administrator in their own environment; DSRclone connects through its governed adapter only when configured.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: NONE; default timeout: 60s.

## Input / Output

Supported targets: API. Capabilities: API_DISCOVERY, SPEC_IMPORT. Output format: JSON; parser: postman-collection. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
