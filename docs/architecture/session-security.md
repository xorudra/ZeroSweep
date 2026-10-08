# Session Security (Prompt 23)

Sessions are server-side records (`UserSession`) keyed by the SHA-256
hash of an opaque 32-byte token — the token itself is never stored.

- **Fixation**: every login (password, MFA-completed, SSO, passkey)
  mints a brand-new session; no pre-auth identifier is honored (§122).
- **Lifetimes**: idle + absolute limits from organization policy,
  clamped by the SDK (idle ≤ absolute; sane bounds) (§42).
- **Revocation**: per-session, per-user, admin-driven, and automatic on
  suspension, deprovisioning, password reset/change and MFA reset.
  Revocation is effective at the next validation (§123).
- **Privilege freshness**: validation reads role/status from the CURRENT
  membership/user rows — demotion applies immediately (§124).
- **Step-up**: sensitive actions can require a fresh MFA proof within a
  10-minute window (`stepUpFresh`); sessions record `stepUpAt`.
- Listing exposes device summaries and timestamps only — never IPs in
  full or token material (§43).
