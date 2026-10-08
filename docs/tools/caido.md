# Caido

Modern web security proxy (Prompt 8 §13): traffic analysis, endpoint/request collection and issue import where the installed version supports it; capabilities detected per deployment.

- **Slug:** `caido`
- **Category:** WEB
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: CUSTOM_ALLOWLIST; default timeout: 1200s.

## Input / Output

Supported targets: WEB_APPLICATION, API. Capabilities: PROXY, TRAFFIC_ANALYSIS, ENDPOINT_DISCOVERY, REQUEST_COLLECTION, ISSUE_IMPORT. Output format: JSON; parser: caido-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
