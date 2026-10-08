# Remediation Runbook (Prompt 31, Operations)

## Daily operation

- Drive the tick (`POST /api/v1/remediation/tick`, also invoked by the
  scheduler): SLA evaluation (warning/at-risk/breach), exception
  expiry sweep, ticket sync, regression detection. Each pass is
  idempotent and records its own events.
- Watch the queue (`/remediation/findings`): OVERDUE and BREACHED
  first, then FIX_CLAIMED cases waiting on verification capacity.

## Breach handling

A breach is a recorded fact, not an alarm to silence: check the case
timeline (pauses are explicit rows with reasons + approvers), the
owner assignment history, and escalate via the NotificationRouter
policies. Never edit a due date directly — recalculation is the
audited path and refuses silent shortening.

## Verification backlog

Verification jobs stuck in ERROR usually mean a scan gate denial
(unverified target / unapproved assessment) — fix the authorization
through the normal assessment flow, then request verification again.
Do not work around gates.

## Provider outages

Work items in FAILED carry the provider error and a backoff time.
Retry is explicit and safe (same work item, same idempotency key).
NOT_CONFIGURED means no connector instance is registered — that is an
administrator configuration task (secret REFERENCE only).
