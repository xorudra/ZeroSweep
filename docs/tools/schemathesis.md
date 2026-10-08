# Schemathesis

Schema-based API testing from imported OpenAPI documents (Prompt 9 §15/§62), restricted to safe conformance checks and operations the API operation policy approves — state-changing operations are excluded before execution.

- **Slug:** `schemathesis`
- **Category:** API
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 900s.

## Input / Output

Supported targets: API. Capabilities: SCHEMA_BASED_API_TESTING, API_VALIDATION. Output format: XML; parser: schemathesis-junit. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
