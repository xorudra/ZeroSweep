# GraphQLmap

GraphQL endpoint discovery/fingerprint support (Prompt 9 §28). The platform records inventory facts only — exploitation payloads are never replayed.

- **Slug:** `graphqlmap`
- **Category:** API
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 300s.

## Input / Output

Supported targets: GRAPHQL. Capabilities: GRAPHQL_ANALYSIS. Output format: TEXT; parser: graphqlmap-text. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
