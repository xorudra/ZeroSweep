# Falco

Runtime security sensor — events arrive through the trusted ingestion path; DSRclone never deploys the sensor (Prompt 13 §57–§63).

- **Slug:** `falco`
- **Category:** CONTAINER
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: CUSTOM_ALLOWLIST; default timeout: 300s.

## Input / Output

Supported targets: KUBERNETES_CLUSTER, DOCKER_HOST. Capabilities: RUNTIME_SECURITY_EVENTS. Output format: JSONL; parser: falco-events. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
