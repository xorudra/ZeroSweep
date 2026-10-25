# OWASP ZAP connector

**Product class:** interactive proxy scanner — `ZapConnector`
(`packages/security-sdk/src/proxy/`), exposed to the orchestration engine
through the standard adapter lifecycle. ZAP is driven through its REST
API; the API is **never** exposed to ZeroSweep users (§5).

## Modes

| Mode | Risk | Default | Notes |
|---|---|---|---|
| Proxy / passive analysis | PASSIVE | enabled in `WEB_BASELINE`+ | Alerts from ZAP's passive scanner only |
| Web crawling (spider) | LOW | templates cap it | In-scope URLs only; logout URLs filtered (§47) |
| Endpoint discovery / import | PASSIVE | on | Site URLs + HTTP messages imported, scope-checked |
| Alert import | PASSIVE | on | Normalized through the Phase 7 pipeline |
| Active scan | **INTRUSIVE** | **disabled** | Governed: see `docs/security/active-scan-approval.md` |

## Configuration

1. Run a ZAP daemon on a **private network** reachable from the worker
   (never expose the ZAP API to users or the internet).
2. Server configuration maps the instance's `endpointReference` to the
   daemon URL and approval flag:
   `DSRCLONE_SCANNER_ENDPOINTS={"ZAP_DAEMON_PROD":{"baseUrl":"http://10.0.0.5:8080","approvedInternal":true}}`
   (private addresses require `approvedInternal`; loopback, link-local and
   cloud-metadata addresses are always blocked).
3. Put the ZAP API key in the worker environment under the instance's
   `credentialReference` name. It is sent as the `X-ZAP-API-Key` header
   from the trusted worker boundary only — never to the frontend, Redis,
   logs or audit records.
4. Register the instance in **Settings → Scanner Instances** and run a
   health check.

## Behaviour

- One ZAP **context per assessment** (`dsrclone-<assessmentId>`), created
  at run start and removed in cleanup, always (§6). Contexts are never
  shared across tenants.
- Scope include/exclude regexes are derived from the approved scope
  snapshot; out-of-scope URLs in ZAP's site tree are recorded as
  out-of-scope endpoints, never promoted (§30/§31).
- Passive alerts are imported as **unverified** findings with ZAP's own
  risk/confidence mapped through the explicit tables in
  `severity.ts` — never auto-confirmed (§7/§34/§35).
- Session expiry (authenticated profile) surfaces as an
  `auth_session.expired` scan event; the scan continues with anonymous
  coverage and partial results rather than retrying credentials (§23).
- If no healthy ZAP instance is configured, scans report the connector
  as `NOT_CONFIGURED`/`UNAVAILABLE` and the passive stage is skipped —
  ZeroSweep never fakes ZAP output (§66).

## API surface used

`/JSON/core/view/version`, context `newContext` / `includeInContext` /
`excludeFromContext` / `removeContext`, spider `scan` / `status`,
`pscan/recordsToScan`, `core/alerts`, `core/urls`, `core/messages`,
`core/message`. Calls are SSRF-guarded (`assertScannerEndpointAllowed`)
and rate-limited by the connector's governed limits (§45).
