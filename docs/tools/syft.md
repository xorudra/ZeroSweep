# Syft

SBOM generation for container images and filesystems (Prompt 13 §12).

- **Slug:** `syft`
- **Category:** CONTAINER
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: CONTAINER_IMAGE, SOURCE_REPOSITORY. Capabilities: SBOM_GENERATION, IMAGE_ANALYSIS. Output format: JSON; parser: syft-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
