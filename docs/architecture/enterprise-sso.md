# Enterprise SSO (Prompt 23)

Per-organization providers of type OIDC or SAML (`EnterpriseSsoProvider`
+ typed config rows). Client secrets and IdP signing material are stored
as secret references or public certificates only.

## OIDC

Authorization Code + PKCE (S256). Discovery documents are validated
against the configured issuer (an issuer mismatch is fatal). ID tokens
are validated strictly: RS256 only, JWKS signature, issuer, audience,
expiry, issued-at window and nonce — hostile fixtures (forged signature,
wrong audience, expired, nonce mismatch) are proven rejected in tests.

## SAML

SP-initiated flow with a dependency-free validator: XXE rejected before
parsing; only enveloped `rsa-sha256` signatures with SHA-256 digests and
inclusive C14N over the Assertion are accepted; issuer, audience,
recipient, InResponseTo and time conditions are enforced; assertion IDs
are consumed exactly once (replay table). Encrypted assertions report
`NOT_SUPPORTED` honestly — the build ships no XML-encryption stack.

## Identity resolution

Users resolve by normalized email. JIT provisioning (when enabled on the
provider AND not disabled by org policy) creates the account with an
unusable random password and the provider's default role (VIEWER unless
configured). Group claims NEVER grant roles directly — only the approved
`ScimGroupMapping` table does (§87).
