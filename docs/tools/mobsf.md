# MobSF

MobSF static-analysis connector (Prompt 17 §13–§17): submits ONLY authorized artifacts to the administrator-registered trusted ScannerInstance; credentials are secret references on the instance (§14). Unconfigured = NOT_CONFIGURED.

- **Slug:** `mobsf`
- **Category:** MOBILE
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: MOBILE_APP. Capabilities: MOBILE_STATIC_ANALYSIS, MANIFEST_ANALYSIS, CODE_ANALYSIS, BINARY_ANALYSIS, CERTIFICATE_ANALYSIS, NETWORK_SECURITY_CONFIG_ANALYSIS. Output format: JSON; parser: mobsf-report. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
