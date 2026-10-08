# API Key Authentication (Prompt 23)

Keys are `dsr_live_`-prefixed, high-entropy (32 random bytes), and shown
exactly once at creation/rotation. Storage is prefix + SHA-256 hash only.

- **Closed scope catalog**: `findings:read`, `assets:read`, `scans:read`,
  `scans:create-safe`, `reports:read`, `reports:create`, `targets:read`,
  `vulnerabilities:read`, `notifications:read`. Shell, raw tool
  execution, approval and administration scopes do not exist and cannot
  be requested (§79).
- **Authentication** checks hash match, revocation, expiry, exact scope,
  and (for service-account keys) that the account is ACTIVE and returns
  its bound workspace (§82–83, §134–136).
- Organization policy can disable personal tokens and cap key lifetimes;
  rotation mints a replacement then revokes the old key (overlap, §81).
- Usage records store the PREFIX only — a full credential is never
  logged (§83).
