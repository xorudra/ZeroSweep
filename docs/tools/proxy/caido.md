# Caido connector

**Product class:** interactive proxy — `CaidoConnector`. Caido is a
modern proxy toolkit whose API surface varies by installed version, so
this connector **detects capabilities from the connected deployment**
and only uses generic, documented shapes (§13/§14):

- Health probe → product/version identification. A reachable instance
  whose version cannot be confirmed reports **DEGRADED**, never HEALTHY.
- Request collection: exported request/response history (JSON envelope
  `{ "requests": [...] }`, optionally under a GraphQL-style
  `{ "data": { ... } }` wrapper) → normalized `HttpTransaction`s with
  hashes and redacted display copies.
- Findings import: `{ "findings": [...] }` envelopes → normalized
  findings through the same Phase 7 correlation/risk pipeline.
- Endpoint discovery from observed traffic (scope-checked, §30).

Unknown or partially-shaped responses produce **warnings, not invented
findings** — if a future Caido version changes its export shape, the
import degrades honestly instead of fabricating data (§66).

## Configuration

Same pattern as every connector: run Caido where the worker can reach
it, map the instance's `endpointReference` in
`DSRCLONE_SCANNER_ENDPOINTS`, keep any credential as an environment
reference, register the instance in **Settings → Scanner Instances**,
health-check it. Manual Caido JSON exports can also be imported via
`POST /scanners/import` with `format: "caido-json"`.
