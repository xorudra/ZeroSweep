# Kiterunner

API route discovery with platform-governed route wordlists (Prompt 9 §13/§14). Discovers routes only — no authorization testing, no data modification.

- **Slug:** `kiterunner`
- **Category:** API
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: API. Capabilities: API_DISCOVERY, ROUTE_DISCOVERY. Output format: JSONL; parser: kiterunner-jsonl. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
