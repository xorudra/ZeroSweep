# SLA Engine (Prompt 20 sections 28-30)

Workspace policies (`VmSlaPolicy`) define triage / remediation /
retest deadlines per severity x priority, adjusted by environment,
asset criticality and finding type. Applying a policy writes
`triageDueAt`, `dueAt`, `retestDueAt` onto the finding; states are
derived (ON_TRACK / DUE_SOON / OVERDUE / PAUSED / NOT_APPLICABLE).
Closed findings are NOT_APPLICABLE. A pause requires an auditable
reason and is recorded in finding history. The shipped default
policy is data in the SDK (`DEFAULT_VM_SLA_POLICY`); workspaces
override it by creating their own policy rows.
