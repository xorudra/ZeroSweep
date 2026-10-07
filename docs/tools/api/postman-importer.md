# Postman collection importer

**Platform importer** (`PostmanCollectionImporter`,
`packages/security-sdk/src/api/`), endpoint
`POST /api/v1/api-security/imports/postman`. Health: HEALTHY
(platform code, no binary).

Imports a Postman collection (v2.x) into API inventory: requests
become endpoint records with `{param}` path templates intact, folders
and request names become operation metadata, and the collection's
base becomes an `ApiService`.

## Secret handling (§11)

- Collection auth values and secret-named variables are **dropped
  during parsing** — they never reach the database, logs or audit
  records.
- An optional environment document can be imported alongside: only
  variable NAMES marked secret survive, returned as
  `secretReferences` so an administrator can bind real values through
  the secret-reference system — the values themselves are discarded.

## Guards (§66/§74)

Same hostile-input treatment as every importer: 10 MiB cap, strict
JSON parsing, nesting/node/string limits. Imports produce inventory
only — never findings.
