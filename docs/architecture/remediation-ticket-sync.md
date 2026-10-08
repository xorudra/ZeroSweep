# Remediation Ticket Synchronization (Prompt 24 §46–§54)

`JiraProjectMapping` routes findings (type/team/asset-group, with a
workspace default) to a Jira project + issue type (§47).
`RemediationTicket` is unique per (finding, integration): creation is
idempotent, so a workflow can never mint duplicate tickets (§124).

Ticket bodies are built from sanitized finding views through a fixed
template (§50) and pass the secret scrubber — a raw secret can never
reach Jira.

## Sync (§51–§54)
External statuses map onto OPEN / IN_PROGRESS / RESOLVED / CLOSED and
update the TICKET only. **A closed ticket is not a resolved finding**
(§52): the finding lifecycle changes solely through the platform's
evidence/retest policy.

Bidirectional sync is a three-way comparison against the last-synced
snapshot. One-sided changes apply cleanly; two-sided changes to the
same field create a `TicketSyncConflict` (§126). Conflicts are
resolved by an analyst (keep local / take external) — the platform
never silently overwrites either side (§53).
