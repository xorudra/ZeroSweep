# Binary Debug Lab (Prompt 18 §64–§74)

Controlled debugging exists as a **governed record + policy engine**,
not as a console. There is no endpoint that attaches a debugger, and
no unrestricted GDB/Python/shell surface exists anywhere (§68/§93).

## Policy (`evaluateBinaryDebugPolicy`)

A session is ELIGIBLE only when **all** hold:

- artifact environment is `LAB` (PRODUCTION is BLOCKED, always);
- artifact authorized + target VERIFIED;
- a **separate** approver with `APPROVE_BINARY_DEBUG` approved
  (separation of duties — self-approval is INVALID), approval unexpired;
- no kill switch active at session/binary/workspace/global level
  (integrates with the Prompt 16 `ValidationKillSwitch` table);
- operations are all in the typed catalog (`START_APPROVED_FIXTURE`,
  `SET_APPROVED_BREAKPOINT`, `INSPECT_REGISTER_METADATA`,
  `INSPECT_BOUNDED_MEMORY`, `CAPTURE_CRASH_METADATA`,
  `TERMINATE_SESSION`) with no command/script-shaped parameters;
- network policy defaults to `NO_NETWORK`; timeout is hard-capped at
  1800s; budgets clamp like the rest of the platform.

Prohibited actions (credential extraction, process injection,
arbitrary debugger commands, attaching to production processes, …)
are refused by name.

## Honest provisioning state

No `BINARY_DYNAMIC_LAB` debugger transport is provisioned in this
build. An eligible, approved session therefore evaluates to
**NOT_PROVISIONED** at run time — it never fabricates a debugging run.
GDB is a DISABLED-outside-LAB descriptor and pwndbg an
APPROVAL_REQUIRED descriptor; neither has an executing adapter.

## Crash triage (§75–§77)

Captured crashes dedupe by a fingerprint of exception type +
normalized stack + faulting function + lineage (raw addresses are
normalized away), and triage as `LIKELY_SECURITY_RELEVANT` /
`NEEDS_REVIEW` / `LIKELY_NON_SECURITY` / `UNKNOWN`. Exploitability is
never claimed automatically, and crash handling never weaponizes.
