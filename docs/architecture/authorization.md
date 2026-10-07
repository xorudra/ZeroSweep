# Authorization boundaries

- **Identity**: JWT (Bearer) issued by `apps/api` auth module; passwords are
  bcrypt-hashed. Payload carries user id, organizationId and role — and the
  backend re-loads tenant state for sensitive checks.
- **RBAC** (backend guards, never frontend-only): OWNER — full organization
  control; ADMIN — users/workspaces/settings, approvals, credentials;
  SECURITY_ENGINEER — targets, scope, assessments, scan requests;
  ANALYST — findings triage, reports, approved validation; VIEWER — read-only.
- **Tenancy**: Organization → Workspace → everything else. Cross-organization
  access is denied in services and again in the SDK policy engine
  (`ORGANIZATION_MISMATCH`).
- **Target authorization**: scans are refused unless the target's ownership
  verification is VERIFIED and the assessment is APPROVED. Verification is a
  real check (DNS TXT lookup / HTTPS well-known file / admin manual approval) —
  never auto-faked.
- **Tool policy**: `evaluateToolPolicy` gates every execution: enabled,
  healthy, target-type compatible, verified, in scope, approval tier by risk
  (PASSIVE/LOW/MODERATE/INTRUSIVE/RESTRICTED — RESTRICTED denied by default),
  credential references present, concurrency available, internal targets blocked.
- **Audit**: logins, target/scope changes, approvals, scan requests/cancels,
  report generation, credential creation and role changes are written to
  AuditLog without secrets.
