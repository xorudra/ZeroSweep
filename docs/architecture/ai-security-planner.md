# AI security planner (Prompt 36 §41–§50)

Plans let the copilot propose multi-step analyst work without ever
executing it.

## Composition (§41/§42)

A plan is a deterministic structure: objective, task type, workspace,
the authorization snapshot hash it was validated against, and steps
with capability, target references, dependencies, risk class,
required permission, approval requirement and expected evidence.
The AI cannot invent capabilities: every step's capability must be a
gateway tool (§27).

## Validation (§43–§46, §150)

The validator is deterministic code (SDK `validateAiPlan`), checking
tenant binding, snapshot freshness, target authorization (VERIFIED
target + APPROVED assessment for scan steps), scope compatibility,
permissions, tool availability, step risk vs the approval ceiling,
estimated cost vs budget, and scan-profile governance (§75–§78:
approved profiles only; high-impact profiles need explicit
approval; remediation-only tasks cannot contain scan steps).
Verdicts: VALID / REQUIRE_MODIFICATION / REJECTED. If validation
cannot run, execution fails closed (§150).

## Approvals (§48–§50, §143)

Approval-required plans wait in AWAITING_APPROVAL. Approval is a
human act recorded with identity and a 24h expiry: the AI can never
approve (§49), approvers cannot be "AI"/"SYSTEM", HIGH+ risk
requires separation of duties, expired approvals cannot be reused,
and execution re-validates against the CURRENT snapshot before any
step runs (§46).
