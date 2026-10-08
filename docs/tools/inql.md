# InQL

GraphQL introspection capture and schema analysis (Prompt 9 §27). Introspection availability is inventory, never a finding by itself (§29).

- **Slug:** `inql`
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

Supported targets: GRAPHQL. Capabilities: GRAPHQL_ANALYSIS, GRAPHQL_SCHEMA_ANALYSIS. Output format: JSON; parser: inql-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
