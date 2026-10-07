# Schemathesis (safe schema-based API testing)

**Adapter:** `SchemathesisAdapter` (`packages/security-sdk/src/api/`),
stage `SAFE_SCHEMA_TESTING`.

Runs Schemathesis against an imported OpenAPI/Swagger schema and
converts its JUnit XML report into findings through the Phase 7
pipeline — and **only** its safe check subset:

```
not_a_server_error, status_code_conformance,
content_type_conformance, response_schema_conformance,
response_headers_conformance
```

## Safety posture (§17/§62)

- The plan REQUIRES a schema location from the guarded import store
  (worker-derived stage input); without one the adapter refuses to
  plan — it never guesses a schema URL.
- Operations are partitioned by the API operation policy
  (`docs/security/api-operation-policy.md`). Non-SAFE operations with
  known operationIds are excluded via `--exclude-name`;
  `--include-method` is pinned to `GET,HEAD,OPTIONS`; the stateful
  phase is never enabled; one worker, no auth headers from the tool.
- `allowStateChanging` exists as configuration for a future approved
  profile. **The worker never sets it.**
- Blocked operations are counted in the result metrics and emitted as
  `api.operation_blocked` events — the audit trail shows what was NOT
  run, and why.

## Health

Reports UNAVAILABLE when the `schemathesis` binary is absent. JUnit
output is parsed with the XXE-safe XML parser shared with the proxy
importers.
