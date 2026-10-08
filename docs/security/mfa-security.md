# MFA Security (Prompt 23)

- TOTP secrets are generated server-side, shown ONCE at enrollment, and
  stored AES-256-GCM-encrypted under a platform key that never touches
  the database. Verification persists the last accepted time-step;
  replaying a code from an accepted step is rejected (§28, §119).
- Login challenges are hashed, single-use, 10-minute, attempt-bounded
  tokens bound to the pending login — a challenge is not a session.
- Policies: OPTIONAL / REQUIRED_FOR_ADMINS / REQUIRED_FOR_ALL (§25).
  Enrolled users are always challenged. A policy with no break-glass or
  recovery path cannot be used to lock everyone out (§100 checks also
  guard MFA-adjacent enforcement).
- Recovery codes: 10 high-entropy codes, shown once, SHA-256-hashed at
  rest, single-use; regenerating destroys the old set (§29/30, §120).
- Administrator MFA reset revokes ALL of the user's methods, recovery
  codes and sessions, and is audited (§37).
