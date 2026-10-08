# kube-hunter

Kubernetes discovery — automated runs are passive-only by policy; intrusive checks are classified and never executed (Prompt 13 §42/§43).

- **Slug:** `kube-hunter`
- **Category:** CONTAINER
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: KUBERNETES_CLUSTER. Capabilities: KUBERNETES_SECURITY_DISCOVERY, KUBERNETES_POSTURE_TESTING. Output format: JSON; parser: kube-hunter-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
