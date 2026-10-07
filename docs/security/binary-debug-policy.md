# Binary Debug Policy (Prompt 18 §64–§74, §94)

- Debugging requires: LAB environment + authorized artifact + VERIFIED
  target + isolated lab worker + network policy (default NO_NETWORK)
  + hard timeout (≤ 1800s) + budget + kill switch + a **separate**
  approver. Missing approval ⇒ `PENDING_APPROVAL`; any hard failure
  ⇒ `BLOCKED`. Decisions and reasons are stored on the session record.
- Only typed operations exist. Requests carrying GDB commands, shell
  commands, script bodies or r2 commands are refused, the session is
  BLOCKED, and the attempt is audited `BINARY_DEBUG_ACTION_BLOCKED`
  (§114). The refused content is never persisted as an instruction.
- Permissions (§94): `REQUEST_BINARY_DEBUG` (OWNER/ADMIN/
  SECURITY_ENGINEER), `APPROVE_BINARY_DEBUG` (OWNER/ADMIN),
  `RUN_BINARY_DEBUG`, `VIEW_BINARY_DEBUG_EVIDENCE`,
  `MANAGE_BINARY_POLICIES` (OWNER/ADMIN). Separation of duties is
  enforced in the service, not just the UI.
- Kill switches integrate with the Prompt 16 validation kill-switch
  table (organization/workspace/scan/target/session levels); an
  active switch terminates eligibility and is audited.
- Session lifecycle is audited end to end: `BINARY_DEBUG_REQUESTED`,
  `BINARY_DEBUG_APPROVED`, `BINARY_DEBUG_STARTED`,
  `BINARY_DEBUG_COMPLETED`, `BINARY_DEBUG_CANCELLED`. Unrestricted
  memory content is never logged (§120).
- In this build no debugger transport is provisioned: eligible
  sessions report `NOT_PROVISIONED` at run time rather than
  fabricating activity (§72).
