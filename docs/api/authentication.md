# API Authentication (Prompt 40 §159/§160)

- Base path: `/api/v1`. Human sessions use Bearer JWTs from
  `/auth/login` (with MFA/SSO per Prompt 23); service accounts use API
  keys (Organization → API keys) with least-privilege scopes.
- Tenant context comes from the token — there is no
  `organizationId` parameter a caller can use to cross tenants (§133).
- Platform routes (`/platform/*`) additionally require the
  platform-admin flag + §136 permissions.
- Webhooks (`/product/billing/webhook/:provider`) are unauthenticated
  by token but require a valid provider signature within the replay
  window (§23).
- The full route inventory is the OpenAPI document served by the API;
  API docs must stay versioned with the API (§286).
