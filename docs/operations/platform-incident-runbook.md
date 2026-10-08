# Platform Incident Runbook — DSRclone

## First five minutes

1. Check `/api/v1/health` (aggregate) and `/api/v1/health/ready`:
   which dependencies are down vs degraded?
2. Check the operational alerts (deploy/monitoring/prometheus-rules.yaml)
   and recent deploys — did a rollout coincide?
3. Declare severity: SEV1 = platform down / tenant data at risk / audit
   writes failing; SEV2 = a dependency down with degradation; SEV3 =
   partial feature loss (AI service, object storage downloads).

## Common plays

- **API 5xx spike**: check dependency_up gauges; if PostgreSQL is down,
  readiness already removed pods from rotation — work the database, not
  the API. Roll back the newest deploy if errors track the rollout.
- **Authorization denial spike**: could be probing or a bad config push.
  Pull AuditLog `POLICY_DENIED`/`SCOPE_VIOLATION` records; denials are the
  platform working as designed — do NOT "fix" by widening scope.
- **Audit write failures (SEV1)**: auditability is a security invariant.
  Freeze scan starts (scale worker pools to 0) until audit persistence is
  restored; preserve all logs.
- **Break-glass used**: verify the linked incident, confirm the session
  ended, schedule the 24h review (access is audited and alerted by design).
- **Suspected credential compromise**: DR runbook, credential-compromise
  sequence — rotate first, investigate second.

## Communications

Status updates name what is KNOWN (dependency states from health
endpoints, alert names) and what is NOT yet known. Never announce a
recovery before the smoke flow passes and the scheduler lease check is
clean.
