# AWS Inventory Connector

Read-only AWS inventory (Prompt 14 §16): account structure, IAM, network, storage, encryption and logging metadata. No data-plane access, no mutations (§7/§13).

- **Slug:** `aws-inventory`
- **Category:** CLOUD
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: AWS. Capabilities: CLOUD_INVENTORY, CLOUD_POSTURE, IDENTITY_INVENTORY, RELATIONSHIP_ANALYSIS. Output format: JSON; parser: aws-inventory. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
