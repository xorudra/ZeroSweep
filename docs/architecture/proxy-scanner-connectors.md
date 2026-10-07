# Proxy scanner connectors — architecture (Prompt 8)

Interactive scanners (ZAP, Burp, Caido) do not fit the CLI adapter
model: they are long-lived services with sessions, contexts and
traffic state. DSRclone models them with a dedicated abstraction,
`InteractiveScannerConnector`
(`packages/security-sdk/src/proxy/connector.ts`), and adapts it into the
existing `SecurityToolAdapter` lifecycle so orchestration, policy,
budgets and result processing treat connectors exactly like other tools.

## Contract (§3)

`checkAvailability`, `healthCheck`, `connect`, `disconnect`,
`validateConfiguration`, `createContext`, `configureScope`,
`configureAuthentication`, `importEndpoints`, `startPassiveAnalysis`,
`getProgress`, `getIssues`, `exportArtifacts`, `startActiveScan`
(policy-gated, disabled by default), `cancel`, `cleanup`.

## Trust boundaries

- **Instances, not URLs.** A `ScannerInstance` stores an opaque
  `endpointReference` name. Server configuration
  (`DSRCLONE_SCANNER_ENDPOINTS`) maps names to real endpoints; scan
  requests and API clients can never supply a scanner destination
  (§16/§17). Every outbound call passes `assertScannerEndpointAllowed`:
  loopback/link-local/metadata always blocked, private ranges only when
  the server config marks the instance `approvedInternal`.
- **Secrets are references.** ZAP API keys, Burp bridge credentials and
  session credentials are named references resolved only inside trusted
  boundaries (API health checks, workers). They never reach the
  frontend, Redis payloads, logs, audit records or finding text (§20).
- **Contexts are per-assessment and per-tenant** (§6): created at run
  start, destroyed in cleanup — always, even on failure.
- **Instances resolve from the database in trusted stores** (worker
  `PrismaScannerInstanceProvider`, API plan builder) — workspace row
  first, then org-wide — never from queue payloads.

## Pipeline position

- Plan: `PASSIVE_SECURITY_ANALYSIS` runs after `SAFE_VULNERABILITY_SCAN`
  in the web templates; `ToolSelector` picks only healthy, configured
  connectors (NOT_CONFIGURED is a rejection). With no connector, the
  stage completes empty — no simulation fallback — and the runner emits
  `passive_analysis.skipped`. `ACTIVE_SECURITY_ANALYSIS` exists in the
  stage library but in **no** profile template (§38).
- Execution: the worker's `StageExecutor` drives the connector lifecycle
  and the adapter returns one envelope (issues + endpoints + transactions
  + websockets + session status) as the execution's raw artifact.
- Results: `ResultProcessor` normalizes transactions (scope verdicts,
  API classification, hashes, redacted copies, `#tx-<n>` artifact refs);
  the Prisma store persists `HttpTransaction` / `WebSocketEndpoint`
  rows (metadata only — raw bytes stay in object storage, §26) and the
  findings flow through the **same** Phase 7 normalization →
  correlation → risk pipeline, so ZAP + Burp + Nuclei reports of one
  issue become **one canonical finding with all sources preserved**
  (§33/§36).
- Imports: `POST /scanners/import` accepts ZAP JSON, Burp XML, Caido
  JSON and HAR under strict format/size guards (§61/§62) and merges
  into existing scan findings by canonical fingerprint.

## Health semantics (§53)

`HEALTHY` / `DEGRADED` / `UNAVAILABLE` / `MISCONFIGURED`, plus the
first-class `NOT_CONFIGURED` (no instance, or reference unresolvable in
server config — reported, never hidden). Version and license state are
recorded on the instance at health-check time.
