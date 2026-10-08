# EASM Exposure Classification & Drift

## Exposure states (`classifyInternetExposure`)

`INTERNET_EXPOSED` requires positive evidence (public DNS, an HTTP
response, or an observed service). `NOT_OBSERVED` requires an actual
check that found nothing — absence of evidence stays `UNKNOWN`,
never silently "safe". Cloud metadata endpoints and localhost are
explicitly **not** public evidence.

## Sensitive services

Database, administration, remote-management, and development/debug
service classes observed on an internet-exposed asset produce the
highest-severity risk signals. Signals feed RiskEngine V3 context and
the SOC alert path (P28) with fingerprint dedupe; EASM does not keep
a second scoring system.

## Drift & baselines

- Baselines (`EasmBaseline`) are immutable, versioned, content-hashed
  snapshots of a program's surface; creating one never mutates an
  older baseline.
- Drift types: `ASSET_ADDED`, `ASSET_DISAPPEARED`, `SERVICE_ADDED`,
  `SERVICE_REMOVED`, `TECHNOLOGY_CHANGED`, `CERTIFICATE_CHANGED`,
  `DNS_CHANGED`, `OWNERSHIP_CHANGED`, `EXPOSURE_CHANGED`.
- **Flapping filter**: snapshot-diff drift starts
  `PENDING_CONFIRMATION`; only a repeat sighting opens it (and raises
  a SOC alert when HIGH/CRITICAL). Service/DNS/certificate changes
  are recorded immediately because they come from direct observation
  diffs, not presence/absence noise.
- **Disappearance**: governed by `disappearanceThreshold` (default 3
  consecutive missed runs). Disappeared assets are retained —
  history is evidence.
