# Authenticated Web Scanning (Prompt 32 §49–§54)

## Profiles and references

Authenticated testing uses Prompt 6 `SessionProfile` /
`AuthenticationProfile` records. A profile stores the credential
**reference**, field/header **names**, login URL and mode — never a
credential value, never a script. `WebVaptTarget.authenticationProfileId`
and `WebVaptScanPlan.authenticationProfileId` carry the reference
through planning; the worker resolves the reference through the secret
injection path at execution time.

## Sessions (§51–§53)

- Each scan run gets an isolated session context (`WebScanSession`):
  separate cookies/storage per run, no cross-target reuse.
- `WebScanSessionManager` responsibilities: establish, validate,
  refresh and terminate sessions; detect expiry mid-run (the stage is
  skipped with `AUTHENTICATION_FAILED`, never silently unauthenticated).
- The session record stores presence flags and fingerprints only.
  Cookie/token **values** never enter the record, logs, evidence or
  reports; session **use** is audited (`AUTH_PROFILE_USED`) by
  reference.
- MFA/SSO flows are supported through user-provided session profiles;
  the platform never automates credential entry against an IdP.

## Roles

Multi-role testing compares role matrices through the authorization
matrix (see `web-vapt-authorization.md`) using user-provided authorized
identities — fixture identities in verification, real test accounts
only as governed references in production use.
