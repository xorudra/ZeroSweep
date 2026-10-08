# RC1 Administrator Guide (Prompt 39 §308)

## First boot

1. Deploy with the operations handoff (`rc1-operations-handoff.md`).
   The production seed creates **no** users — register the first
   account through the product UI/API; it becomes the organization
   OWNER.
2. Set production secrets before first boot; the API refuses
   placeholder configuration.
3. Confirm `GET /api/v1/health` reports every dependency ok.

## Organizations, workspaces, users

- An organization is the tenant root; workspaces partition work
  inside it. Tenant isolation is enforced server-side on every query
  — administrators cannot "see across" tenants through the product.
- Roles: OWNER / ADMIN / SECURITY_ENGINEER / ANALYST / AUDITOR /
  VIEWER (plus portal roles CLIENT_MANAGER / CLIENT_REMEDIATOR /
  CLIENT_VIEWER for client accounts). Grant the least role that fits;
  UI visibility is never the enforcement layer.
- Enterprise identity (P23): configure OIDC/SAML per organization,
  SCIM provisioning at `/scim/v2` (bearer token is org-bound), MFA
  policy, and break-glass accounts (max 3/org) **before** enforcing
  SSO — enforcement without break-glass + a verified domain is
  refused by design.

## Targets, scope, approvals

- Nothing scans without a VERIFIED target and an APPROVED assessment
  bound to a scope snapshot. Admins approve; separation-of-duty rules
  apply where configured (risk acceptance, high-risk verification).
- Discovered assets stay candidates until promoted through the EASM
  chain; discovery never expands scope.

## Tools & workers

- The tool catalog ships DISABLED except governed adapters. Enable a
  tool only after installing its operator-provided binary; licensed
  tools (Burp Pro, Nessus, IDA, Binary Ninja…) need the
  organization's own license — the platform never bundles them.
- Keep scanner workers segmented: they are the only components with
  target egress and elevated capture capabilities (each justified in
  the tool registry).

## Platform operations

- Platform-ops (P38) is the admin surface for deployments, worker
  fleet, backups, and the six-level kill switches. Build identity
  (version/commit) is shown there — RC1 reports `1.0.0-rc.1`.
- Access reviews, API keys (shown once, scoped, hashed at rest) and
  audit-log review live under organization/security settings.
