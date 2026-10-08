# OWASP ZAP

Open-source web proxy/scanner via its daemon API (Prompt 8 §4): passive analysis first, per-assessment contexts, endpoint + alert import. Active scanning INTRUSIVE, approval-gated, disabled by default.

- **Slug:** `owasp-zap`
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

Supported targets: WEB_APPLICATION, API. Capabilities: PROXY, PASSIVE_ANALYSIS, CONTEXT_MANAGEMENT, ENDPOINT_IMPORT, ISSUE_IMPORT, WEB_CRAWLING, ENDPOINT_DISCOVERY, VULNERABILITY_SCANNING, ACTIVE_WEB_SCANNING. Output format: JSON; parser: zap-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
