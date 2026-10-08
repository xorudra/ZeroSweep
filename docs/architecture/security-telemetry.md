# Security Telemetry (Prompt 28 §3–§13)

## Canonical event

Provider events are normalized into `SecurityTelemetryEvent`
(SDK: `packages/security-sdk/src/soc/normalize.ts`): event time,
source + source category, event category/action, asset and identity
references, severity, classification, and a flat attributes bag.
The raw record is preserved **by reference only** (`rawReference`) —
never copied into the canonical store (§6).

## Ingestion discipline

- **Authentication (§9):** scoped API key (`telemetry:ingest`),
  ACTIVE service account with the same scope, an enabled signed
  integration in the same workspace, or a user session held by a
  SOC lead. Every mode is verified before any event is read.
- **Idempotency (§11):** fingerprint = provider event id when
  present, else a stable hash of the canonical identity. Replays
  are duplicates, never second events.
- **Integrity (§7):** each stored event carries a SHA-256 content
  hash over its canonical body; incident evidence referencing a
  telemetry event is verified against it (§143).
- **Bounds (§10/§12):** per-workspace rate limit, 64 KB payload
  cap, 40 attributes, 512-char values, nested objects dropped.
- **Redaction (§13/§157):** secret-shaped attribute keys are
  redacted wholesale and values pass the platform secret scrubber
  before storage — planted credentials never reach the store,
  search, alerts or AI context.
- **Source health (§115/§116):** sources declare an expected event
  interval; the evaluation tick opens `TelemetryDataGap` records
  for silent sources and resolves them when events resume. A
  silent source is a detection blind spot and is surfaced as one.
