# Permission-aware retrieval / RAG (Prompt 36 §10–§13)

Retrieval is a security boundary, not a convenience.

## Source types (§11)

FINDING, FINDING_OBSERVATION, EVIDENCE_METADATA, ASSET, ASSET_GRAPH,
SBOM_COMPONENT, VULNERABILITY_INTEL, SCAN, COVERAGE, REMEDIATION,
VERIFICATION, CLOUD_INVENTORY, CONTAINER_INVENTORY,
KUBERNETES_INVENTORY, MOBILE_FINDING, BINARY_FINDING, SOC_ALERT,
SOC_INCIDENT, GRC_EVIDENCE, REPORT, DOCUMENTATION.

## Rules

- Loaders are workspace-scoped at the data layer; cross-tenant rows
  cannot be returned, and foreign IDs behave as nonexistent (§105).
- Each source maps to an AI permission; sources the user may not read
  are skipped AND disclosed to the answer layer (§21) so gaps are
  visible instead of silently papered over.
- Classification ceilings apply per workspace policy; SECRET data is
  never sent to external providers (§6).
- Resource-level ACLs apply inside the workspace (§13): remediation
  evidence, cloud inventory and incident material respect their own
  access rules, not just workspace membership.
- Vulnerability intelligence is global reference data attached only
  through THIS workspace's findings, labelled with the dataset's
  real sync state (the production dataset stays EMPTY /
  NEVER_SYNCED until a governed sync runs — fixture data is never
  presented as production).
- Freshness is assessed per record (CURRENT / STALE / UNKNOWN) and
  surfaced in answers (§17/§21).
