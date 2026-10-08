# CloudMapper

CloudMapper (AWS) account-graph import (Prompt 14 §27): public nodes and network structure from recorded exports become exposure evidence in the asset graph.

- **Slug:** `cloudmapper`
- **Category:** CLOUD
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: AWS. Capabilities: AWS_NETWORK_ANALYSIS, AWS_ACCOUNT_VISUALIZATION, PUBLIC_EXPOSURE_ANALYSIS. Output format: JSON; parser: cloudmapper-import. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
