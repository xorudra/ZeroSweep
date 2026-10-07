# InQL (GraphQL schema inventory)

**Adapter:** `InqlAdapter` (`packages/security-sdk/src/api/`), stage
`GRAPHQL_ANALYSIS`.

Runs InQL against a discovered GraphQL endpoint to retrieve its
introspection schema and records the INVENTORY: queries, mutations,
subscriptions and types, whether a schema was available, and whether
authentication appears required.

## Posture (§28/§29)

- Introspection-only. No query is executed against the target's data,
  and mutations are counted, never called.
- Introspection being enabled is an **observation, not a finding** —
  the adapter produces zero findings from schema presence alone.
- The same introspection importer backs manual GraphQL schema imports
  in the API, so scan-discovered and user-imported schemas land in the
  same `GraphqlService` records.

## Health

Reports UNAVAILABLE when the `inql` binary is absent.
