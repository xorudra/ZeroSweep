# Authenticated scanning (Prompt 8 §18–§24)

## Profiles

`SessionProfile` describes a reusable session: type (`ANONYMOUS`,
`AUTHENTICATED`, `API_AUTHENTICATED`), a `credentialReference` (a NAME —
the secret lives in the vault/worker environment), cookie/header
**policies** (names and handling rules, never values), and a validation
rule. `AuthenticationProfile` adds the mechanism (`FORM`, `BASIC`,
`BEARER`, `API_KEY`, `COOKIE`, `OAUTH`, `CUSTOM_HEADER`) with field
names and a login URL. **Arbitrary login scripts are not supported**
(§19) — a mode that cannot be expressed declaratively cannot run.

## Rules

- Secrets are resolved only in the trusted worker boundary at execution
  time; they never appear in the database, the queue, logs, audit
  records, the frontend, or finding descriptions (§20).
- **Session validation is evidence-based** (§22): after login, the
  connector requests the profile's known authenticated URL and requires
  the expected status and/or marker. A cookie merely existing proves
  nothing.
- **Expiry is terminal for the session** (§23): an expired/invalid
  session emits `AUTH_SESSION_EXPIRED` (scan event
  `auth_session.expired`), the scan continues with anonymous-level
  coverage and is marked accordingly — credentials are never retried in
  a loop.
- Logout endpoints are detected and excluded from crawling (§47);
  form submissions are classified `SAFE` / `UNKNOWN` / `SENSITIVE` /
  `DESTRUCTIVE`, and conservative profiles never auto-submit `UNKNOWN`
  or worse (§46). CSRF tokens encountered during navigation are used
  for navigation only — never logged or displayed (§48).
- Role-based test identities can be recorded as separate profiles now;
  **cross-user authorization abuse automation is not part of this
  phase** (§24).
