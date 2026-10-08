# CodeQL

Semantic code analysis engine with governed query suites + SARIF import (Prompt 12 §28–§31). Build-needing languages degrade as BUILD_REQUIRED — target code is never built.

- **Slug:** `codeql`
- **Category:** SOURCE_CODE
- **License:** OPEN_SOURCE
- **Risk level:** LOW
- **Requires approval:** no
- **Availability:** NOT_CONFIGURED

## Installation

Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.

## Worker requirement

Execution mode: CONTAINER; network policy: NO_NETWORK; default timeout: 3600s.

## Input / Output

Supported targets: SOURCE_REPOSITORY. Capabilities: SAST, SECURITY_QUERY_ANALYSIS, DATAFLOW_ANALYSIS. Output format: SARIF; parser: sarif. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
