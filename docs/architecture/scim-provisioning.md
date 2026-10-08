# SCIM 2.0 Provisioning (Prompt 23)

Endpoints under `/scim/v2` (Users, Groups, ServiceProviderConfig),
authenticated by a dedicated per-organization SCIM bearer token (SHA-256
hash + prefix at rest; rotation invalidates the old token immediately).
The token determines the organization — there is no tenant parameter, so
cross-tenant confusion is structural, and user JWTs/API keys are never
accepted here (§67, §141).

- **Filters** are parsed by a strict allowlist parser; anything else
  (e.g. injected `or 1 eq 1`) is rejected — filters are evaluated in
  memory, never compiled to raw SQL.
- **Groups → roles** flow only through administrator-approved
  `ScimGroupMapping` rows. An unmapped group grants the default VIEWER
  role and nothing more (§71, §131).
- **Deprovisioning disables, never deletes**: user deactivated,
  memberships revoked, sessions revoked, history preserved (§69).
- `ScimExternalRecord` tracks IdP↔local identity links per organization.
