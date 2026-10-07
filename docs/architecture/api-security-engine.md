# API Security Engine (Prompt 9)

The API security layer turns discovered and imported APIs into governed
inventory and safe, evidence-backed checks. It is built entirely on the
existing foundations: the Tool Adapter SDK lifecycle (Prompt 3), the
scan DAG (Prompt 4), the endpoint inventory (Prompts 5–6), the findings
pipeline (Prompt 7) and the session/redaction model (Prompt 8).

## Pipeline

The `API_ASSESSMENT` profile runs, in order:

1. `AUTHORIZATION_CHECK` / `SCOPE_VALIDATION` — the standard gates: the
   target must be VERIFIED and the assessment APPROVED before anything
   runs.
2. `API_DISCOVERY` (platform) — consolidates the API inventory known so
   far (imported specifications, discovered services, endpoints).
3. `SPEC_IMPORT` (platform) — summarizes the guarded import store for
   the target: specifications and their operation counts.
4. `ROUTE_DISCOVERY` (Kiterunner) — API route discovery under the
   governed wordlist manager (baseline = SMALL list).
5. `AUTH_MAPPING` (platform) — maps registered API auth contexts and
   declared service authentication. References only; no secret is
   resolved or used.
6. `SAFE_SCHEMA_TESTING` (Schemathesis) — schema-based testing
   restricted by the API operation policy (see
   `docs/security/api-operation-policy.md`): only SAFE operations can
   execute, state-changing operations are excluded by name, DELETE is
   never automated.
7. `JWT_ANALYSIS` (platform) — resolves the workspace's registered
   credential REFERENCE names inside the worker boundary; values that
   parse as JWTs are inspected (decode + claim/algorithm observations).
   Raw tokens never persist — only fingerprints and redacted claims.
8. `GRAPHQL_ANALYSIS` (InQL / GraphQLmap) — introspection-driven
   schema INVENTORY. Introspection being enabled is an observation,
   never a finding by itself; mutations are never executed.
9. `WEBSOCKET_INVENTORY` (platform) — counts the scan's persisted
   WebSocket endpoints and how many presented authentication material.
10. `SAFE_VULNERABILITY_SCAN` (Nuclei) — restricted to the `nuclei`
    adapter for this profile, under the Prompt 7 SAFE template policy
    (including the API templates `exposed-openapi-spec` and
    `api-debug-endpoint-exposure`).
11. `PASSIVE_SECURITY_ANALYSIS` — the Prompt 8 connector stage (ZAP /
    Burp / Caido / mitmproxy traffic import); completes honestly as
    skipped when nothing is configured.
12. `API_FINDING_NORMALIZATION` → `NORMALIZATION` → `CORRELATION` →
    `RISK_ANALYSIS` → `REPORT_GENERATION` — the Phase 7 tail: API
    findings merge with every other source under canonical
    fingerprints, with provenance preserved.

`API_COMPREHENSIVE` remains architecture-only in this phase (spec §40);
`API_ASSESSMENT` is the §39 baseline.

## Imports are inventory, never findings

OpenAPI/Swagger documents, Postman collections, Insomnia exports and
GraphQL introspection results enter through guarded importers
(`POST /api/v1/api-security/imports/*`):

- Size caps (10 MiB), strict JSON, YAML through a JSON-schema-only
  parser (unknown tags rejected), nesting/node/string limits, and
  external `$ref` values detected and recorded as warnings — **never
  fetched** (imports are hostile input, §66/§74).
- Postman/Insomnia secrets: values are dropped during parsing; only
  variable NAMES survive, as secret references (§11).
- Persistence writes specification metadata (checksum + object-storage
  reference — raw bytes are not kept in Postgres), schema STRUCTURE
  (property name → type; never example values, §36), services and
  endpoints. Endpoint rows are written directly so `{id}` path
  templates survive — URL canonicalization would percent-encode them.
- An import can create **zero findings**. Findings come only from
  checks: Schemathesis conformance results, JWT inspection, governed
  Nuclei API templates.

## Data model additions

`ApiService`, `ApiSpecification`, `ApiSchema`, `GraphqlService`,
`JwtProfile`, `ApiAuthContext`, `AuthorizationTestCase`,
`TestDataProfile`; `Endpoint` gains `operationId`, `path`,
`contentTypes`, `requestSchemaId`, `responseSchemaId`, `authRequired`,
`authSchemes`; `WebSocketEndpoint` gains `authPresent`.

Authorization test cases (§42) are design records — identity A/B
contexts over an object-identifier template, born `NOT_APPROVED`.
Nothing in this phase executes them; controlled validation is a later
phase behind its own approval gate.

## Honesty rules

- Adapters whose binaries are absent report UNAVAILABLE; mitmproxy
  with no registered instance reports NOT_CONFIGURED. Neither is an
  error, and neither is ever simulated.
- JWT fixtures and tests use obviously-fake tokens only (`alg: none`
  test tokens with literal `FAKE-SIGNATURE`); no real credential is
  ever needed to exercise this pipeline.
- Route names alone never become findings. A `/admin`-style API route
  is inventory until a check produces evidence (§51).
