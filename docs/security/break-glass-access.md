# Break-Glass Access (Prompt 23)

SSO misconfiguration must never lock an organization out of its own
security platform (§58/59):

- Up to 3 named administrators per organization can be enrolled as
  break-glass accounts BEFORE SSO is enforced. Enabling/enforcing SSO
  without at least one enrollment (or a verified domain recovery path)
  is refused by the API (§100) — in services, not just the UI.
- Under enforcement, password login is refused for everyone EXCEPT
  enrolled break-glass admins, and only AFTER their password verifies
  (unauthenticated callers learn nothing).
- Every break-glass login stamps `lastUsedAt`, writes a
  `BREAK_GLASS_LOGIN` audit record AND an authentication event for
  alerting (§59/§137 fixtures prove both the refusal and the audited
  success path).
- Break-glass is a recovery mechanism, not a backdoor: enrollments are
  listed, auditable and revocable by security administrators.
