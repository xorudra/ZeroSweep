# Mobile Dynamic Lab (Prompt 35 §71–§87)

## Lab contract
- Devices are DSRclone-managed emulators or dedicated test devices
  on an isolated test network. Personal devices are never enrolled.
- A device becomes usable for dynamic work only when an OWNER/ADMIN
  marks it AUTHORIZED (registration alone is not authorization,
  §74). Revoke by setting `authorizationStatus` back — in-flight
  requests then BLOCK.
- Instrumentation modules are registered by hash and approved
  separately from registration (§80). Approval is OWNER/ADMIN
  (`APPROVE_MOBILE_INSTRUMENTATION` / §135
  `RUN_APPROVED_RUNTIME_INSTRUMENTATION`).

## Session lifecycle
REQUESTED → policy (kill switch, device authorization, module
approval, prohibited-action screen) → APPROVED or BLOCKED (reasons
recorded + audited) → RUNNING → COMPLETED/TERMINATED → cleanup:
stop app, remove temporary test data, revoke temporary secrets,
release device, clear proxy configuration (§87).

## Honest state
No dynamic transport is wired in the local environment: sessions
are governed records whose statuses reflect policy outcomes, and
tool health reports ADB/mitmproxy as NOT_CONFIGURED. Nothing in
the lab claims an execution that did not happen.
