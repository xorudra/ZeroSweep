# Validation Kill Switch (Prompt 16 §43/§44)

## Levels

Kill switches exist at six levels, most specific wins when resolving a
session's fate:

`GLOBAL` → `ORGANIZATION` → `WORKSPACE` → `SCAN` → `TARGET` → `SESSION`

Activating any level blocks new matching validations and terminates
matching active sessions. SCAN/TARGET/SESSION switches require the
scope reference they apply to.

## Emergency cancellation

- The worker checks active switches **before** starting a session and
  **continuously during** execution (a watcher polls the store; a
  switch flipped mid-flight cancels the session and records
  `KILL_SWITCH_ACTIVATED` as the termination reason).
- Cancelling a running validation request through the API plants a
  SESSION-level switch for its live session — the same termination
  path, no special cases.
- Every validation process also has a **hard timeout** (dead-man
  switch, §44): budget duration is enforced by the budget tracker even
  if nothing else fires.

## Administration

- Activation requires `MANAGE_VALIDATION_POLICY` (OWNER/ADMIN) and is
  audited as `KILL_SWITCH_ACTIVATED` with actor, level, scope and
  reason (§80/§81).
- Clearing a switch records who cleared it and when; the switch row is
  kept (inactive) as the audit trail.
- Kill-switch activations are a first-class observability metric on
  the validation dashboard (§82).

## Relationship to scan emergency stop

The scan-plane emergency stop (Prompt 4) halts scan execution. The
validation kill switch is its validation-plane counterpart: separate
because validations have their own sessions, budgets and tenants, and
a validation freeze must be possible without touching scans (and vice
versa).
