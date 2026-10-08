# Gobuster

Directory and file discovery (dir mode only in this platform). Implemented Prompt 6.

- **Slug:** `gobuster`
- **Category:** WEB
- **License:** OPEN_SOURCE
- **Risk level:** MODERATE
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: SCOPE_ONLY; default timeout: 600s.

## Input / Output

Supported targets: WEB_APPLICATION. Capabilities: CONTENT_DISCOVERY, DIRECTORY_DISCOVERY, FILE_DISCOVERY. Output format: TEXT; parser: gobuster-text. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
