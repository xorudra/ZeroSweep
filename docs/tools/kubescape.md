# Kubescape

Kubernetes posture and manifest analysis with compliance framework mapping (Prompt 13 §44).

- **Slug:** `kubescape`
- **Category:** CONTAINER
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1800s.

## Input / Output

Supported targets: KUBERNETES_CLUSTER, KUBERNETES_MANIFEST, CONTAINER_IMAGE. Capabilities: KUBERNETES_POSTURE, MANIFEST_ANALYSIS, COMPLIANCE_ASSESSMENT. Output format: JSON; parser: kubescape-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
