# Web VAPT Authorization (Prompt 32 §6, §97–§102)

## The chain

No V2 record authorizes anything by itself. Active testing requires,
in order: target **VERIFIED** (ownership) → assessment **APPROVED**
(active authorization) → scope snapshot frozen → plan approved for
HIGH modules where applicable. Preflight re-checks the chain on every
run; a missing or expired link is `BLOCKED` (§173/§174).

## Permissions (§166/§167)

`VIEW_WEB_VAPT`, `MANAGE_WEB_TARGETS`, `RUN_WEB_VAPT`, `RUN_API_VAPT`,
`MANAGE_VAPT_PROFILES`, `MANAGE_VAPT_AUTH`, `VIEW_VAPT_EVIDENCE`,
`CANCEL_VAPT_SCAN`, `RUN_TARGETED_VERIFICATION`, `EXPORT_VAPT_REPORT`
layer over workspace roles as in every phase. `RUN_HIGH_RISK_WEB_TESTS`
is admins-only and is necessary-but-not-sufficient for HIGH modules:
the §16 gate also requires the explicit profile, the active
authorization and a recorded approval reference.

## Authorization test matrices (§97–§100)

A matrix hangs off a Prompt 9 `AuthorizationTestCase` design record.
Rows use **user-provided authorized identities** and fixture/template
resource identifiers only — broad enumeration of real object IDs is
rejected at validation (§98). Expected vs observed access is compared
by `AuthorizationTestingService` logic in the SDK:

- match → no finding;
- mismatch → a **candidate finding** (CWE-862, HIGH confidence for
  DENY-expected/ALLOW-observed, MEDIUM for the reverse) stored on the
  matrix entry for evidence review;
- `NOT_TESTED` rows stay untested — never silently passed.

Candidates materialize into canonical findings only through the
governed pipeline with a linked scan and evidence.

## Business logic (§101/§102)

Scenarios are human-defined: preconditions, authorized identities,
safe steps, expected behavior. Steps describing destructive actions
(delete/destroy/drop/transfer funds/refund/purchase/…) are rejected at
creation. Evaluation compares a **recorded** observation against the
expected behavior; a deviation is a review signal, not an automatic
finding. The platform does not pretend generic scanners automate
business logic.
