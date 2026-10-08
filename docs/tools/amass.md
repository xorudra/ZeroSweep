# Amass

Attack surface mapping and asset discovery via OSINT.

- **Slug:** `amass`
- **Category:** RECON
- **License:** OPEN_SOURCE
- **Risk level:** PASSIVE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: INTERNET_READ_ONLY; default timeout: 600s.

## Input / Output

Supported targets: DOMAIN. Capabilities: SUBDOMAIN_DISCOVERY, DNS_DISCOVERY. Output format: JSONL; parser: amass-jsonl. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
