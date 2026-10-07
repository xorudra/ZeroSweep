# ROADtools Connector (Prompt 14 §29/§30)

## Purpose
Entra ID (Azure AD) **defensive** analysis: role assignments,
application permissions and risky identity relationships from recorded
ROADtools exports.

## Capabilities
`DIRECTORY_ANALYSIS`, `IDENTITY_INVENTORY`

## Supported target types
AZURE (registered cloud accounts)

## Risk level
LOW — defensive import only.

## Execution mode
EXTERNAL_API (import) over recorded exports in the worker artifact
store; with no export it reports NOT_CONFIGURED honestly.

## Hard boundary (§106)

Only the defensive half of ROADtools data is ever parsed: role
assignments and application permissions, mapped to the canonical IAM
rules (`iam-admin-equivalent`, `iam-wildcard-actions`). Offensive
directory operations — token manipulation, device-code phishing,
directory writes of any kind — are **never invoked, never wrapped,
never exposed** by this platform.
