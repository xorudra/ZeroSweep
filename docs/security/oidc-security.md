# OIDC Security (Prompt 23)

- Authorization Code flow with PKCE S256; `state` is a hashed,
  single-use, 10-minute challenge record; the code verifier never
  leaves the server (§48, §125).
- Discovery is fetched from the configured issuer and must self-report
  the same issuer; endpoints must be HTTPS URLs.
- ID tokens: RS256 ONLY (no `none`, no HS256 confusion), signature
  verified against JWKS, strict issuer/audience/expiry/iat checks, and
  the nonce must match the stored challenge value (§49, §126).
- Client secrets are secret references (`env:<VAR>`), resolved at token
  exchange time; an unresolvable reference yields NOT_CONFIGURED, never
  a fallback.
- SSO failures are generic ("SSO login failed") at the boundary and
  specific only in server-side authentication events.
