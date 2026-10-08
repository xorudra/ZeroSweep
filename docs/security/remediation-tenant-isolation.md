# Remediation Tenant Isolation (Prompt 31 §149)

Every remediation row carries `workspaceId`, and every read/write is
scoped by it:

- Cases are loaded with `{ id, workspaceId }` — a case id from
  another workspace is indistinguishable from a nonexistent one
  (404, no existence leak).
- Work-item and campaign idempotency keys are checked against the
  caller's workspace; a cross-workspace key collision is an error,
  never a silent cross-tenant return.
- Verification jobs, exceptions, snapshots and regression events are
  all fetched through their case, which is itself tenant-scoped.
- The queue, analytics, SLA dashboard and reports aggregate only the
  caller's workspace.

Tests (§149) assert that another workspace cannot read a case or
ensure one against a foreign finding.
