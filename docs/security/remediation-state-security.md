# Remediation State Security (Prompt 31 §119/§157)

Every state-changing endpoint performs, in order: workspace tenant
resolution → §121 permission check → input validation → **guarded
state-machine transition** → audit record → transactional-outbox
event. A rejected transition writes nothing.

Direct paths around the engines do not exist:

- The generic `PATCH /remediation/:id` refuses VERIFIED_FIXED,
  FIX_CLAIMED, ACCEPTED_RISK, FALSE_POSITIVE and CLOSED — each belongs
  to its workflow (verification, claims, exceptions, triage, closure).
- Ticket adapters never mutate finding state (Prompt 31 §69); the
  only finding writes flow through the Prompt 11 lifecycle service or
  its guarded mirrors with legal from-states.
- AI assistance holds no transition capability at all: the assist
  endpoint refuses mark-fixed instructions outright, and its plan
  drafts pass the same trusted-intelligence check as human plans.
- Bulk operations use a closed action list that excludes verify/close
  by construction.

Segregation of duties (§122): exception approver ≠ requester; on
high-risk findings the fix claimer ≠ verifier; a policy-required
second approver differs from both.
