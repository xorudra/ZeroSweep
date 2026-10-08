# Security Event Bus (Prompt 24 §75–§77)

Producers publish canonical `SecurityEventEnvelope`s — `eventId`
(stable, UUID), `eventType`, `workspaceId`, `timestamp`,
`resourceType`, `resourceId`, `schemaVersion` ("1.0"), and a
sanitized payload. Scanners and services NEVER call integrations
directly; they publish events, and integration deliveries subscribe.

Versioned schemas mean a consumer written against 1.0 keeps working
when fields are added; breaking changes require a new schemaVersion,
never a silent shape change (§77).

Outbound webhook event types (§73): `finding.created`,
`finding.updated`, `finding.resolved`, `finding.reopened`,
`risk.changed`, `scan.completed`, `scan.failed`, `report.ready`,
`asset.exposure.changed`, `quality_gate.failed`.

SIEM events (§62) use the separate §64 shape — references and scores
only, serialized as JSON, CEF or LEEF.
