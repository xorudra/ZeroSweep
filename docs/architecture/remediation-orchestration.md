# Remediation Orchestration (Prompt 31)

ZeroSweep Prompt 31 turns findings into finished work: every canonical
finding gets at most one ACTIVE `RemediationCase`, and the case — not
the ticket, not the scanner, not the AI — is where remediation state
lives. The pipeline is:

Triage → Ownership → Priority → SLA → Plan → Ticket → Fix →
Fix Claimed → Safe Verification → Evidence Comparison →
Verified Fixed → Closure → Monitoring → Regression → Reopen.

## Non-negotiables

- A finding is **never** marked fixed because a ticket closed, a
  developer clicked resolved, a scanner stopped seeing it, or an AI
  believes it is fixed. `VERIFIED_FIXED` is reachable only through the
  verification engine; `CLOSED` only through the closure engine.
- Verification rides the existing gated scanner architecture
  (VERIFIED target + APPROVED assessment + scope/policy). The
  orchestration layer cannot mint approvals or widen scope.
- Suggested fixes remain recommendations. The platform never applies
  patches or changes target systems.
- Every state change writes four records: the status-history row, an
  audit entry, a transactional-outbox event, and the updated case.

## Modules

`apps/api/src/modules/remediation/` — cases, triage, ownership, SLA,
plans, tickets, verification, closure, exceptions, campaigns,
regression, analytics, AI assistance, reports, bulk and the tick.
Pure decision logic lives in `packages/security-sdk/src/remediation/`
(state machine, SLA math, verification policy, ticket payload
building, campaign progress, analytics, NL query plans) and is unit
tested without any I/O.
