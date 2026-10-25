# AI action boundary (Prompt 21 §7/§8/§81–§84/§99/§120)

## The boundary

```
AI → Proposed Action → Policy Engine → Human / Workflow Approval
   → Existing Typed Service → execution
```

Never `AI → shell`. The copilot's only write surface is its own
records: request logs, messages, citations, suggested patches
(drafts), feedback, knowledge documents and `AiActionProposal` rows.

## Proposals (§83/§84)

The closed proposal vocabulary is `REQUEST_VALIDATION`,
`REQUEST_RETEST`, `ASSIGN_FINDING`, `CREATE_REPORT_DRAFT`. A proposal
records action type, target, summary, scope and the permission the
owning workflow will require. The API response states plainly that
nothing has executed. A reviewer decision (APPROVED / REJECTED /
DISMISSED) records intent for the owning workflow — the validation,
retest, assignment and reporting workflows remain the only executors,
under their own gates (verified target + approved assessment, plan
hashes, kill switches).

## No generic tools (§81/§82)

If a future model supports tool calls, only typed read-only ZeroSweep
tools may be exposed (`getFinding`, `getAsset`, `searchCVEs`,
`getRiskExplanation`, `queryAuthorizedFindings`). Shell, exec,
terminal, raw SQL, filesystem write and arbitrary HTTP are never
exposed as AI tools. The current build needs no tool calls at all:
the platform assembles context server-side.

## Refusals

Execution-shaped user input ("run a scan…", "execute shell…") is
detected, refused with an explanation, logged `POLICY_BLOCKED` and
audited `AI_POLICY_BLOCKED`. The AI API surface itself accepts no
shell commands, scanner commands, raw SQL, scripts or tool
definitions (§115).
