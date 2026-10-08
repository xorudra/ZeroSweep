# SBOM Correlation Rebuild (Prompt 30 §46–§59 operations)

Correlation results (`ComponentVulnerabilityMatch`, `ComponentReachabilityAssessment`) are **derived data**: they can be rebuilt at any time from stored workspace components + global intelligence without losing anything except evaluation timestamps.

Rebuild paths:

- Per workspace: `POST /api/v1/vulnerability-intelligence/sbom/correlate` (requires MANAGE_VULNERABILITY_INTELLIGENCE) — idempotent upserts keyed by (workspaceId, componentId, cveId); `firstDetected` is preserved across rebuilds.
- After a large intelligence import: re-run correlation per affected workspace, then re-enrichment (`POST /vulnerability-intelligence/re-enrich`) to refresh finding snapshots and risk.
- Disaster recovery (§157): tenant SBOMs, matches, enrichments and risk history are ordinary Postgres rows covered by the standard pg_dump backup path; global intelligence is rebuildable from governed feed snapshots, so a restore may either restore both or restore tenant data and re-import intelligence + rebuild correlation.
