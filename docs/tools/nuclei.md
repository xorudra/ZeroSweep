# Nuclei

Template-based vulnerability scanner, restricted to the governed SAFE template policy (Prompt 7 §4).

- **Slug:** `nuclei`
- **Category:** WEB
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 1200s.

## Input / Output

Supported targets: WEB_APPLICATION, DOMAIN, API. Capabilities: VULNERABILITY_SCANNING, MISCONFIGURATION_DETECTION, EXPOSURE_DETECTION, TECHNOLOGY_VALIDATION. Output format: JSONL; parser: nuclei-jsonl. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
