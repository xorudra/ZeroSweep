# Service Accounts (Prompt 23)

Service accounts are non-human identities for CI and integrations:

- Organization-scoped, optionally bound to exactly ONE workspace.
- Least-privilege typed scopes only (same closed catalog as API keys).
- No interactive login, no password, never inherit a user's permissions,
  and never receive broader rights than explicitly granted (§74–76).
- Credentials are API keys owned by the account; disabling the account
  denies its keys at authentication time (§82).
- Creation against a workspace outside the caller's organization is
  refused (§136); usage updates `lastUsedAt` for review.
