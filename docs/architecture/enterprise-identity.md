# Enterprise Identity Architecture (Prompt 23)

DSRclone's identity engine layers enterprise authentication ON TOP of the
existing local auth (Phase 1) — it never replaces it. Local accounts keep
working in every configuration; enterprise features activate per
organization.

## Layers

1. **Pure policy/crypto core** — `packages/security-sdk/src/identity/`:
   TOTP (RFC 4226/6238), recovery codes, WebAuthn verification, OIDC
   validation, a dependency-free SAML 2.0 validator, a strict SCIM filter
   parser, session/permission policy, API-key scopes, password policy,
   auth-risk and redirect/CORS rules. No I/O; everything unit-tested with
   hostile fixtures.
2. **API services** — `apps/api/src/modules/identity/`: sessions, MFA,
   WebAuthn, SSO (OIDC + SAML), SCIM, API keys/service accounts,
   governance (policies, domains, invitations, access reviews), and the
   auth-flow completion service. `AuthService` (Phase 1) gained the MFA
   gate, the SSO-enforcement/break-glass gate, login rate limiting and
   server-side session issuance without changing its response contract.
3. **GUI** — settings pages for members, SSO/policy, SCIM, access
   reviews, MFA/passkeys, sessions, API keys and service accounts.

## Honesty rules

- Unconfigured organizations report SSO/SCIM `NOT_CONFIGURED`; nothing is
  ever faked.
- Secrets are secret REFERENCES (`env:<VAR>`) or hashes — never values —
  in the database, API responses and this documentation.
- Verification is fixture-only: a test IdP (generated keys, recorded
  discovery/JWKS, signed fixture assertions) proves the validation logic.
  No live IdP exists in this environment; production interconnect is a
  deployment task, and SAML encrypted assertions report `NOT_SUPPORTED`
  rather than pretending to decrypt.
