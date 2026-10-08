# Security Scheduler (Prompt 22 §6–§28)

`SecuritySchedulerService.tick(now, owner)` is the whole engine —
deterministic in `now`, which is what makes it testable with a fake
clock (§97) and safe to run from any timer.

## Tick pipeline

1. **Lease** (§23/§24): a single `SchedulerLease` row (scope
   `continuous-scheduler`). `decideLease` grants acquisition only to
   the current holder or after expiry; a second node gets
   `acquired: false`. Heartbeats are written on the tick's clock.
   Crash recovery (§119) = lease expiry + idempotent run keys.
2. **Retries**: FAILED runs whose `nextAttemptAt` arrived are
   re-executed first. Only retryable error classes ever land there —
   policy denials are never retried (§21); exhaustion writes a
   `DeadLetterJob` (§22).
3. **Due schedules**: enabled, unpaused, `nextRunAt <= now`, planned
   with queue backpressure (§95: over the depth threshold everything
   defers) and round-robin tenant fairness (§96), plus per-workspace
   concurrency caps (§17).
4. **Missed runs** (§20): due instants collapse per policy — SKIP,
   RUN_ONCE, or CATCH_UP_LIMITED (max 3). Collapsed instants are
   persisted as SKIPPED runs with `MISSED_RUN_SKIPPED`; there is
   never an unlimited backlog.
5. **Per-run gates** (all persisted as ScheduleRun outcomes):
   profile safety class → frequency/budget (§13) → maintenance and
   blackout windows (§15/§16; blackout defers to the blackout end) →
   concurrency + equivalent-run dedupe (§17/§18/§102) →
   authorization recheck (§25) → fresh DNS scope revalidation
   (§26, web/network) → cloud (§27) and repository (§28)
   authorization are rechecked by the same APPROVED/VERIFIED gate
   for their assessment kinds.
6. **Idempotency** (§19): `scheduleRunKey = sha256(scheduleId +
   scheduledFor)` is unique; re-executing an instant returns the
   existing run (`ALREADY_MATERIALIZED`) instead of duplicating work.
7. **Snapshot cadence**: workspaces touched by the tick get a fresh
   snapshot set + drift comparison (§29).

## Schedule kinds

| Kind | Materializes | Outcome |
| --- | --- | --- |
| SCAN | `OrchestrationService.startScan` (all gates re-run inside) | ENQUEUED + scanId |
| REPORT | Prompt 20 ReportSchedule definition executed via VmReportsService | COMPLETED + reportId |
| REVALIDATION | Prompt 16 validation REQUESTS for eligible findings | PENDING_APPROVAL (approval still required; never auto-executed) |
| RETEST | Prompt 11 RetestService via SDK eligibility (RetestRouter + SAFE catalog) | COMPLETED with count |
| INTEL_SYNC | nothing — no data source configured | SKIPPED / INTEL_SOURCE_NOT_CONFIGURED (honest) |

Run-now (`POST /schedules/:id/run`, §82) runs the identical gate
pipeline with the caller as actor. Pausing re-anchors `nextRunAt` on
resume so a paused schedule never unleashes its backlog (§20).
