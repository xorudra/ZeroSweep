# Scheduler Scope Revalidation (Prompt 22 §25–§28)

A schedule is a standing intention, not a standing authorization.
Before **every** materialized run the scheduler re-verifies, in
order:

1. **Assessment authorization (§25).** The assessment must be
   APPROVED *now*. Any later status change (review, suspension,
   expiry workflows) blocks the run with `AUTHORIZATION_EXPIRED`.
2. **Target verification (§25).** The target must still be
   VERIFIED; loss of verification blocks with
   `TARGET_NOT_VERIFIED`.
3. **DNS scope revalidation (§26).** For web/network destinations
   the hostname is resolved **fresh** and passed through the Prompt
   16 `revalidateScope` check against the assessment's approved
   scope rules: out-of-scope hosts, and any resolution landing on a
   protected address (loopback, link-local, metadata, private —
   unless an approved internal engagement applies), block the run.
   This is the DNS-rebinding defense applied at schedule time; the
   worker re-checks again at execution time.
4. **Cloud (§27) and repository (§28) authorizations** are rechecked
   through the same APPROVED-assessment + VERIFIED-target gate for
   their kinds — a cloud account or repository whose authorization
   lapsed cannot be reached by a stale schedule.

Outcomes are persisted ScheduleRuns (BLOCKED with a reason code) and
audited (`SCHEDULE_RUN_BLOCKED`). Policy-class refusals are **never
retried** (§21): retrying an expired approval would be an attempt to
resurrect it, which the design forbids (§99).

Scope can never widen through scheduling: a schedule references the
approved assessment (whose scope is fixed) or a monitoring policy
whose selector only *filters* workspace assessments. Discovered
assets from drift are never selector outputs for intrusive work —
they are not assessments at all.
