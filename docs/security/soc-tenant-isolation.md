# SOC Tenant Isolation (Prompt 28 §126, §154–§156)

Every SOC query is scoped by `workspaceId`, and the workspace is
resolved through the platform tenant guard before any service runs.
Consequences, each covered by tests:

- **Alerts (§154):** fetching another workspace's alert by id
  returns 404 — the record does not exist as far as the caller is
  concerned.
- **Indicators (§155):** indicator search and matching only ever
  see the caller's workspace store; a private indicator in
  workspace A is invisible to workspace B.
- **Incidents (§156):** incident detail, timeline, evidence and
  response actions are workspace-bound in the same way.
- **Ingestion:** telemetry lands only in the authenticated
  workspace. An API key or service account from another tenant
  cannot ingest here — ingestion auth resolves the credential and
  the caller's tenant together.
- **Response effects:** every executable effect re-checks tenant
  ownership at execution time (API keys and sessions by
  organization, integrations/schedules/findings by workspace), so
  a stale or crafted target reference cannot cross tenants.
- **AI context:** the SOC copilot builds facts only from the
  caller's workspace rows; other tenants' records are unreachable,
  not merely unlisted.
