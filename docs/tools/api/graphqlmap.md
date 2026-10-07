# GraphQLmap (GraphQL discovery & analysis)

**Adapter:** `GraphqlmapAdapter` (`packages/security-sdk/src/api/`),
stage `GRAPHQL_ANALYSIS`.

Used for GraphQL endpoint discovery/analysis support alongside InQL:
confirming a GraphQL surface and contributing schema inventory to the
same normalized `GraphqlService` records.

## Posture (§28)

- Discovery and analysis only — no mutation execution, no query
  fuzzing, no exploitation features are wired into any plan.
- Output is inventory. A reachable GraphQL endpoint with introspection
  enabled is recorded as an observation for the assessment report, not
  promoted to a vulnerability without separate evidence.

## Health

Reports UNAVAILABLE when the `graphqlmap` binary is absent.
