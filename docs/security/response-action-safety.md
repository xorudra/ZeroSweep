# Response Action Safety (Prompt 28 §74–§82, §145–§148/§152)

- **Closed catalog.** Only nine predefined defensive actions
  exist. Proposing anything else — including shell-shaped action
  keys — is a 400, not a fallback (§76).
- **Approval before execution.** High-impact actions require
  single or dual approval per the catalog. Execution against a
  non-APPROVED record returns the state and changes nothing (§146).
- **Segregation of duties (§79).** A proposer's approval of their
  own high-impact action is recorded but never counts; the policy
  evaluator reports the SoD reason explicitly. Duplicate approvals
  from one approver count once (§147).
- **Permissions (§145).** Propose, approve and execute are separate
  SOC permissions. A user without the approval permission is refused
  before policy evaluation.
- **Idempotency (§148).** Proposal identity is
  `incident + action + target + nonce`; executions are
  single-shot — a retried execution returns the recorded outcome
  instead of repeating the effect.
- **Tenant-checked effects.** Each effect verifies the target
  belongs to the caller's tenant at execution time.
- **AI boundary (§152).** The SOC copilot may recommend catalog
  actions and playbooks. It holds no execution path: recommendations
  render with `executed: false`, and acting on one means a human
  proposing it through this engine.
- **Honest outcomes.** Executions end as `EXECUTED`,
  `NOT_CONFIGURED` (e.g. ticket creation without an enabled Jira
  integration) or `FAILED` with the reason recorded — never a
  silent success.
