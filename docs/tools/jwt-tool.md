# jwt_tool

JWT INSPECTION only (Prompt 9 §22–§25): decode + claim inventory + algorithm/expiry/sensitive-claim policy checks. No cracking, brute force or tampering exists; raw tokens are never stored.

- **Slug:** `jwt-tool`
- **Category:** API
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: NONE; default timeout: 60s.

## Input / Output

Supported targets: API, GRAPHQL. Capabilities: JWT_INSPECTION, JWT_CONFIGURATION_ANALYSIS. Output format: JSON; parser: jwt-inspection. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
