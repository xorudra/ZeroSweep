# Validation Workflow (Prompt 16)

## Workflow DAG

Every validation executes the same fixed stage order — stages cannot
be skipped, reordered, or added by a requester:

```
AUTHORIZATION → SCOPE REVALIDATION → POLICY → APPROVAL → BUDGET →
SAFE_VALIDATOR → EVIDENCE → CONFIDENCE_UPDATE → REPORT
```

## Request lifecycle

Statuses: `REQUESTED`, `POLICY_REVIEW`, `APPROVAL_REQUIRED`,
`APPROVED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `INCONCLUSIVE`,
`BLOCKED`, `CANCELLED`, `EXPIRED`.

1. **Create** (`POST /api/v1/validations`, `REQUEST_SECURITY_VALIDATION`).
   The requester names a finding and — optionally — a catalog
   validator. Prohibited techniques are refused immediately (and
   audited). Duplicate active validations for the same
   finding + target + validator are refused unless explicitly allowed;
   idempotency keys replay the original request.
2. **Plan**. The plan is generated from the governed template: fixed
   stages, allowlisted typed parameters, budget clamped to
   administrator hard limits. The plan is hashed (SHA-256 over a
   canonical form); the hash identifies the plan forever.
3. **Authorization snapshot**. Immutable at request time: target
   verified state, assessment approval state, allowed techniques,
   scope rules. If authorization is no longer valid at execution,
   validation fails — the worker re-reads live state and refuses on
   any regression.
4. **Policy evaluation** (`ValidationPolicyEngine`): prohibited →
   workspace allowlist → authorization → scope → risk gates →
   `ALLOW` / `DENY` / `REQUIRE_APPROVAL`. Denials are **persisted** as
   `BLOCKED` requests (auditable, counted in metrics) — never hidden.
5. **Approval** when required. Specific to target + finding +
   technique via the plan hash; any plan edit produces a different
   hash and voids the approval. Approvals expire (default 60 minutes;
   INTRUSIVE-class LAB approvals 15 minutes). Higher-risk validations
   require separation of duties: requester ≠ approver. High-criticality
   assets require approval even for LOW_IMPACT.
6. **Dispatch**. Approved requests enqueue IDs only; the worker's
   `ValidationRunner` re-checks everything before executing (kill
   switch → policy with live approval state → scope revalidation with
   fresh DNS resolution → catalog lookup) and only then runs the
   validator through a budget-counting, kill-switch-watched transport.
7. **Evidence & confidence**. Sanitized, checksummed evidence is
   stored; the finding's validation confidence updates per the outcome
   mapping — never its original scanner evidence.
8. **Report**. Reports classify findings as Scanner Detected / Safely
   Validated / Manually Validated / Not Reproduced / Inconclusive, and
   each completed validation has a proof-of-validation summary:
   what, when, target, method, result, evidence reference.

## Cancellation

Cancelling an approved/queued request marks it `CANCELLED`.
Cancelling a **running** request plants a SESSION-level kill switch;
the worker's mid-flight watcher terminates the session and records the
termination reason.

## Scheduled validation

Recurring **SAFE-only** revalidation belongs to the continuous
monitoring scheduler (Prompt 22): intrusive validation is never
scheduled automatically. This phase ships the manual + approval flow;
the scheduler integration is a documented follow-up, not a hidden gap —
see the Prompt 16 section of the README.
