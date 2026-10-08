# Shodan CLI

Shodan search API client; administrator supplies the API key.

- **Slug:** `shodan-cli`
- **Category:** RECON
- **License:** EXTERNAL_API
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: EXTERNAL_API; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: DOMAIN, IP_ADDRESS. Capabilities: SUBDOMAIN_DISCOVERY, SERVICE_DETECTION. Output format: JSON; parser: json. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
