# mitmproxy

Open-source interactive proxy (Prompt 9 §33): API traffic capture, endpoint discovery from observed flows and WebSocket inventory via admin-registered instances. Traffic intelligence only — no findings are derived.

- **Slug:** `mitmproxy`
- **Category:** API
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: CUSTOM_ALLOWLIST; default timeout: 1200s.

## Input / Output

Supported targets: API, WEB_APPLICATION. Capabilities: PROXY, HTTP_TRAFFIC_CAPTURE, API_DISCOVERY, WEBSOCKET_DISCOVERY, ENDPOINT_IMPORT, REQUEST_COLLECTION. Output format: JSON; parser: mitmproxy-flows. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
