# OWASP Dependency-Check

Dependency vulnerability analysis (Prompt 12 §49) against the worker-provisioned database — no installs, no network audits (§57).

- **Slug:** `owasp-dependency-check`
- **Category:** SOURCE_CODE
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 1800s.

## Input / Output

Supported targets: SOURCE_REPOSITORY. Capabilities: SCA, DEPENDENCY_VULNERABILITY_ANALYSIS. Output format: JSON; parser: dependency-check-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
