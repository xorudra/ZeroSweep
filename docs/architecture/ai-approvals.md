# AI approvals & workflows (Prompt 36 §47–§50, §141–§143)

## Workflow states

DRAFT → VALIDATING → AWAITING_APPROVAL → APPROVED → RUNNING →
COMPLETED / PARTIAL / FAILED / CANCELLED, with REJECTED terminal.
Illegal transitions are refused (§47).

## Approval invariants

- Requested by a human user; decided by a human user (§48/§49).
- `approverId` "AI" or "SYSTEM" is refused structurally.
- HIGH/CRITICAL risk: approver ≠ requester (§143 separation of
  duties) under the default SOD_RESTRICTED workspace policy.
- Approvals expire (24h default) and are single-workflow (§50).
- Execution re-validates the plan against the CURRENT authorization
  snapshot; drift or unavailable validation fails closed (§150).

## What execution means

Workflow steps call gateway tools. SAFE_ACTION steps create
proposals/drafts inside the owning governed workflows (scan intake,
remediation orchestration, SOC cases, report drafts). The AI never
performs the underlying action itself; the owning workflow's own
gates decide and execute.
