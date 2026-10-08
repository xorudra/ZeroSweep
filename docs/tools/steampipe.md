# Steampipe

Steampipe governed query packs (Prompt 14 §32): approved CIS/exposure packs only — arbitrary SQL from users or repositories is refused.

- **Slug:** `steampipe`
- **Category:** CLOUD
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: CUSTOM_ALLOWLIST; default timeout: 1800s.

## Input / Output

Supported targets: AWS, AZURE, GCP. Capabilities: CLOUD_QUERY, CSPM. Output format: JSON; parser: steampipe-json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
