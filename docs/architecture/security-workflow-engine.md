# Security Workflow Engine (Prompt 22 §57–§64)

Workflows are **typed documents**, validated by
`packages/security-sdk/src/continuous/workflow.ts`:

- **Triggers** (§58): FINDING_CREATED, FINDING_VERIFIED,
  FINDING_REOPENED, KEV_DETECTED, SLA_DUE_SOON, SLA_OVERDUE,
  NEW_PUBLIC_ASSET, RISK_INCREASED, SCAN_FAILED, REPORT_READY.
- **Conditions** (§59): typed fields (severity, priority,
  environment, assetType, verification, kev, riskScore, owner, tag,
  domain) with typed operators (eq, neq, in, gte, lte, contains).
- **Actions** (§60): CREATE_NOTIFICATION, ASSIGN_FINDING,
  SET_PRIORITY (bounded P0–P4), REQUEST_SAFE_RETEST,
  CREATE_REPORT_DRAFT, CREATE_ANALYST_TASK, ADD_TAG. Each maps to an
  existing governed capability. There is no generic HTTP action, no
  shell action, no code action.

## No arbitrary code (§61/§62)

Validation rejects unknown triggers/fields/operators/actions,
parameters outside each action's allowlist, and any code-shaped key
(`script`, `code`, `command`, `shell`, `python`, `javascript`,
`eval`, `exec`, `function`, `webhook`, `url`, `http`, `sql`,
`query`). The GUI offers selects only — no code editor exists.

## Loop protection (§63)

`checkLoopGuard` enforces three independent stops: maximum depth
(3), lineage (a workflow never appears in its own trigger lineage),
and per-event action dedup keys. A blocked execution is persisted
with status BLOCKED_LOOP — visible, auditable, never silent.

REQUEST_SAFE_RETEST goes through the auto-retest eligibility gate
(RetestRouter + Prompt 16 SAFE validator catalog), so a workflow can
never become a path around the §51–§53 exclusions.
