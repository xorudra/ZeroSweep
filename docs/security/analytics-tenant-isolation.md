# Analytics Tenant Isolation (Prompt 27)

Isolation is enforced at three independent layers:

1. **Ingestion** — an event naming a different organization/workspace
   than the consuming scope is rejected to the dead-letter
   (`TENANT_CONTEXT_MISMATCH`); events are never re-homed (§12).
2. **Storage & queries** — every store/search/aggregation query carries
   `organizationId + workspaceId` predicates. Workspace resolution goes
   through `resolveWorkspace`, which verifies the workspace belongs to
   the caller's organization; foreign workspaces are `404`, not `403`
   (existence is not leaked).
3. **Cache** — cache keys embed organization, workspace, role,
   permission fingerprint and classification ceiling (§122/§142).

Verified by tests: cross-tenant search returns zero results and zero
suggestions (§127); reindex of one workspace leaves another workspace's
documents untouched (§144).
