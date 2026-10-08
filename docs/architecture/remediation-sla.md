# Remediation SLA (Prompt 31 §21–§31)

SLA policies are **configuration**, stored as `RemediationSlaPolicy`
rows (extended in Prompt 31 with version, conditions,
warningThresholds, escalation, verificationRequired,
requiredCleanObservations). Nothing about a target duration is
hardcoded: resolution picks the most specific matching policy
(severity/priority/KEV/exposure/criticality/category conditions) and
falls back to the P11 priority/severity rules of the default policy.
When no configured policy yields a duration, assignment fails loudly
— no due date is ever invented.

Assignment writes a `RemediationSlaSnapshot`: policy id + **version**,
the exact resolution inputs, target hours, start and due date. Policy
edits create a new version; snapshots keep pointing at theirs.

States (ON_TRACK, WARNING, AT_RISK, BREACHED, PAUSED, COMPLETED) are
derived from stored timestamps by the evaluation tick. Paused time
never counts: reasons are a closed list (WAITING_VENDOR,
APPROVED_EXCEPTION, ENVIRONMENT_UNAVAILABLE, OTHER_APPROVED_REASON),
pausing needs `PAUSE_REMEDIATION_SLA`, and APPROVED_EXCEPTION needs a
named approver. WARNING/AT_RISK/BREACHED transitions emit
`REMEDIATION_SLA_*` events and route notifications through the P22
NotificationRouter (external channels stay honestly
RECORDED_NOT_DELIVERED / NOT_CONFIGURED until a provider exists).

Recalculation (§25): a material risk change may propose a new due
date, but an existing due date is **never silently shortened** —
shortening applies only when explicitly allowed.
