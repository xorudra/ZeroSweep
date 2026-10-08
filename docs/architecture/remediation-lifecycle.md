# Remediation Lifecycle (Prompt 31 §5–§9)

States: NEW, TRIAGED, ASSIGNED, PLANNED, IN_PROGRESS, BLOCKED,
FIX_CLAIMED, VERIFICATION_PENDING, VERIFICATION_RUNNING,
VERIFIED_FIXED, ACCEPTED_RISK, FALSE_POSITIVE, DEFERRED, CLOSED,
REOPENED.

The transition table is closed (`REMEDIATION_TRANSITIONS` in the SDK)
and three moves carry extra guards beyond table membership:

- `FIX_CLAIMED` requires the fix-claim workflow (`viaFixClaim`).
- `VERIFIED_FIXED` requires the verification engine (`viaVerification`).
- `CLOSED` from `VERIFIED_FIXED` requires the closure engine
  (`viaClosure`); `ACCEPTED_RISK` requires an approved exception
  (`viaException`); `FALSE_POSITIVE` requires reason + evidence.

Status history is append-only: assignments, pauses, regressions and
reclassifications are new rows, never edits. A case in a terminal
state (CLOSED) can only leave via REOPENED (a regression).

The case mirrors — never replaces — the canonical finding lifecycle
(Prompt 11). Fix claims move the finding to REMEDIATED; verified fixes
walk it REMEDIATED → RETEST_PENDING → RESOLVED through the P11
service; regressions move RESOLVED → NEW. Divergences are recorded in
the closure snapshot rather than hidden.
