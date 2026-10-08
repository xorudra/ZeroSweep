# TruffleHog

High-entropy secret scanning for repositories (Prompt 12 §37). External verification is DISABLED by platform policy (§44).

- **Slug:** `trufflehog`
- **Category:** SOURCE_CODE
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 900s.

## Input / Output

Supported targets: SOURCE_REPOSITORY. Capabilities: SECRET_SCANNING, SECRET_DETECTION, SECRET_VERIFICATION. Output format: JSONL; parser: trufflehog-jsonl. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
