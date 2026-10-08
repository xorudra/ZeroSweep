# Authentication Security (Prompt 23)

- Passwords are bcrypt-hashed (cost 12). SSO/JIT accounts receive an
  unusable random password hash — they can only sign in via their IdP.
- Every authentication failure returns the SAME generic message
  ("Invalid email or password"); failures never reveal whether the
  account exists, the password was wrong, MFA is enabled, or the
  account is disabled (§23, §109).
- Login, reset and MFA attempts are rate-limited per account+IP (§22).
- Account enumeration via password reset is impossible: the reset
  endpoint answers identically whether or not the account exists (§109).
- Successful logins update `lastLoginAt` and write `AuthenticationEvent`
  + audit records; identity observability (§116) aggregates
  success/failure/MFA/session counts per organization.
- Suspended/deactivated users and suspended/revoked memberships cannot
  authenticate through any path (§136 checks apply to API keys too).
