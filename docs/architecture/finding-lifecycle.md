# Finding Lifecycle (Prompt 37 §7–§10)

There is exactly one finding lifecycle. Prompt 11's `VmLifecycleStatus`
is the stored state; Prompt 37 §7's vocabulary is a **projection**
(`@zerosweep/security-sdk` `reporting2/lifecycle-view.ts`):

- NEW → NEW, TRIAGED → TRIAGED, CONFIRMED → CONFIRMED,
  FALSE_POSITIVE → FALSE_POSITIVE, ACCEPTED_RISK → ACCEPTED_RISK.
- IN_PROGRESS / REMEDIATED / RETEST_PENDING project through the
  Prompt 31 case when one exists: case IN_PROGRESS → IN_PROGRESS,
  FIX_CLAIMED → FIX_CLAIMED, VERIFICATION_* → VERIFICATION_PENDING,
  VERIFIED_FIXED → FIXED_VERIFIED (only reachable with a passed
  verification), CLOSED → CLOSED.
- RESOLVED → FIXED_VERIFIED **only** when verification evidence says
  PASSED/CONFIRMED; otherwise CLOSED. DUPLICATE → CLOSED.

Rules that hold across every surface (API, portal, reports, sync):

- Every transition is a FindingHistory event with actor, time and
  reason (§9); no surface mutates state silently.
- AI may suggest a state with reasoning but can never apply one (§10)
  — there is no AI-callable transition path.
- A fix claim is FIX_CLAIMED, never FIXED_VERIFIED (§29/§103); only
  the governed Prompt 31 verification closes a finding (§30).
- Regression reopens through the same machine and increments the
  recurrence/regression counters (§31/§32).
