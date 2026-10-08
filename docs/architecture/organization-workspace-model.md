# Organization & Workspace Model (Prompt 23)

- **User** — a person identity (email + normalized email, account status).
- **Organization** — the tenant. Owns SSO providers, SCIM tokens, security
  policy, domains, service accounts and access reviews. A SUSPENDED
  organization is not operational.
- **Membership** (organization membership) — user × organization with a
  role (OWNER, ADMIN, SECURITY_ADMIN, SECURITY_ENGINEER, ANALYST, MEMBER,
  VIEWER) and a status (ACTIVE/SUSPENDED/REVOKED). Roles are ALWAYS read
  from the current membership row at authorization time — never from a
  stale token claim (§124).
- **WorkspaceMembership** — user × workspace grants inside the
  organization. Organization role is a baseline; workspace roles grant the
  resource-level permissions evaluated by the SDK permission engine
  (explicit DENY wins; a manage grant implies read).

Authorization composition: organization baseline + workspace grants,
evaluated per request by `evaluatePermission` in the security SDK.
