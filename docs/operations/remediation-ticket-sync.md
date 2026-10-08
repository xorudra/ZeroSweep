# Remediation Ticket Sync (Prompt 31 §47–§49, Operations)

Sync pulls provider status + assignee for every live work item and
maps them into canonical states (OPEN / IN_PROGRESS / RESOLVED /
CLOSED). Provider text is data — it is never executed and never
drives the finding lifecycle directly.

Rules operators should know:

- A provider ticket reaching CLOSED creates a **fix claim**
  (source TICKET_SYNC) and moves the case to FIX_CLAIMED. Verification
  is still required; sync will never produce VERIFIED_FIXED.
- Status conflicts (e.g. ticket reopened after closure) surface as
  the work item returning to SYNCED with the new external status; the
  case history records the claim that the closure produced.
- Work items unsynced for more than 7 days are flagged STALE by the
  sync pass so silent sync death is visible.
- FAILED items are not retried by the sync pass; retry is an explicit
  operator action on the same work item.
