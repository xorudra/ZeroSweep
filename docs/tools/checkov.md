# Checkov

Infrastructure-as-code, Kubernetes manifest, Helm and Dockerfile static analysis (Prompt 13 §46) — IaC is never executed.

- **Slug:** `checkov`
- **Category:** CLOUD
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1800s.

## Input / Output

Supported targets: SOURCE_REPOSITORY, CONTAINER_IMAGE, KUBERNETES_MANIFEST, HELM_CHART, KUBERNETES_CLUSTER. Capabilities: IAC_SECURITY, KUBERNETES_MANIFEST_SECURITY, DOCKERFILE_SECURITY, HELM_SECURITY. Output format: JSON; parser: checkov-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
