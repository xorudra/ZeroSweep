# Nmap

Host discovery, port scanning, service/version fingerprinting, OS hinting and governed SAFE NSE checks (Prompt 10). Commands are built only from validated typed configuration.

- **Slug:** `nmap`
- **Category:** NETWORK
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 1200s.

## Input / Output

Supported targets: IP_ADDRESS, CIDR, DOMAIN. Capabilities: HOST_DISCOVERY, PORT_DISCOVERY, SERVICE_DETECTION, VERSION_DETECTION, OS_HINTING, SAFE_NETWORK_CHECKS. Output format: XML; parser: nmap-xml. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
