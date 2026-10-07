# Insomnia export importer

**Platform importer** (`InsomniaImporter`,
`packages/security-sdk/src/api/`), endpoint
`POST /api/v1/api-security/imports/insomnia`. Health: HEALTHY
(platform code, no binary).

Imports an Insomnia export (format 4) into API inventory: workspace
requests become endpoint records (URL templates preserved),
environments contribute the base URL, and the export becomes an
`ApiService` + `ApiSpecification` pair like every other import.

## Secret handling (§11)

Environment values and authentication material in the export are
treated as hostile payload: secret-named values are dropped during
parsing and never persisted; only names can survive, as references.

## Guards (§66/§74)

10 MiB cap, strict parsing, nesting/node/string limits. Imports
produce inventory only — never findings.
