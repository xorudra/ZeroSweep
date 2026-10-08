# Kubernetes Connector

Read-only cluster inventory + posture over registered cluster connections; secret values are never retrieved (Prompt 13 §32–§38).

- **Slug:** `kubernetes-connector`
- **Category:** CONTAINER
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: KUBERNETES_CLUSTER. Capabilities: CLUSTER_INVENTORY, RESOURCE_INVENTORY, POSTURE_ASSESSMENT. Output format: JSON; parser: kubernetes-inventory. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
