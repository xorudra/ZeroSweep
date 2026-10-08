# Prowler

Prowler CSPM (Prompt 14 §23): multi-cloud CIS/posture checks over read-only credential references. FAIL results become findings on canonical cloud rules; PASS is posture evidence only.

- **Slug:** `prowler`
- **Category:** CLOUD
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: AWS, AZURE, GCP. Capabilities: CSPM, CLOUD_POSTURE, COMPLIANCE_QUERY. Output format: JSON; parser: prowler-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
