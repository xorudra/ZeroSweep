# Trivy

Static container image analysis: vulnerabilities, misconfigurations and secret metadata (Prompt 13 §15–§18). Images are never executed.

- **Slug:** `trivy`
- **Category:** CONTAINER
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1800s.

## Input / Output

Supported targets: CONTAINER_IMAGE, CONTAINER_REGISTRY, SOURCE_REPOSITORY. Capabilities: IMAGE_VULNERABILITY_SCANNING, MISCONFIGURATION_SCANNING, SECRET_SCANNING, IMAGE_ANALYSIS. Output format: JSON; parser: trivy-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
