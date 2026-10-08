# Grype

Vulnerability scanner for container images, filesystems and source snapshots (Prompt 12 §51 for source use; Prompt 13 §19 for image use — one adapter, two input kinds).

- **Slug:** `grype`
- **Category:** CONTAINER
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: CONTAINER_IMAGE, SOURCE_REPOSITORY. Capabilities: CONTAINER_SCANNING, SCA, PACKAGE_VULNERABILITY_ANALYSIS, SBOM_ANALYSIS, IMAGE_VULNERABILITY_SCANNING. Output format: JSON; parser: grype-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
