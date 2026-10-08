# API VAPT V2 (Prompt 32)

V2 deepens the Prompt 9 API security engine on the same models
(`ApiService`, `ApiSpecification`, `ApiSchema`, `GraphqlService`,
`JwtProfile`, `ApiAuthContext`, `AuthorizationTestCase`). There is no
parallel API runner: API scans are planned against the governed
operation policy and execute through the canonical pipeline.

## What V2 adds

- **Immutable specification snapshots** (`ApiSpecificationSnapshot`):
  source, version, content hash, endpoint/schema counts and the list of
  referenced hosts that scope validation rejected, frozen at import.
- **Host validation on import (§139/§140):** hosts referenced by an
  OpenAPI/Postman/Insomnia document are checked against the API
  service's scope. Out-of-scope hosts are recorded as rejected — never
  fetched, never trusted.
- **Authorization matrices** over Prompt 9 `AuthorizationTestCase`
  design records (see `web-vapt-authorization.md`).
- **Business-logic scenarios** as human-defined, safe-step-only design
  records with recorded-observation evaluation.
- **Bounded analysis:** Schemathesis stays in the Prompt 9 SAFE check
  classes; GraphQL test generation is bounded by depth/complexity/
  alias/batch limits (`graphql-limits.ts`); state-changing operations
  require explicit profile enablement (§46); every plan carries the
  clamped request budget (§48).

## JWT posture (§55/§56)

Defensive only, unchanged from Prompt 9: structure, algorithm,
expiry, issuer/audience and sensitive-claim inspection via fingerprints.
The platform never stores raw tokens and never performs password
cracking or signature brute-force.

## Profiles

`API_SAFE` and `API_STANDARD` are the only profiles accepted by the API
scan endpoint; both reuse the Prompt 9 operation policy verdicts.
