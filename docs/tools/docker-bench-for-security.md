# Docker Bench for Security

CIS Docker Benchmark host checks — INTERNAL_PRIVILEGED: approved host + dedicated privileged worker only (Prompt 13 §28).

- **Slug:** `docker-bench-for-security`
- **Category:** CONTAINER
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: DOCKER_HOST. Capabilities: DOCKER_CIS_ASSESSMENT, DOCKER_HOST_CONFIGURATION, COMPLIANCE_ASSESSMENT. Output format: JSON; parser: docker-bench-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
