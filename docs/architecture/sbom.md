# SBOM (Prompt 12 §47/§48)

Every source scan's inventory stage can emit a Software Bill of
Materials for the snapshot:

- **Formats:** CycloneDX JSON (spec 1.5) and SPDX (JSON + tag-value).
- **Identity:** components are keyed by Package URL; the document is
  **deterministic** for a given snapshot — its serial/UUID derives from
  the snapshot hash and its checksum is SHA-256 over the canonical
  document, so re-generation over the same inventory reproduces the
  same checksum.
- **Storage:** the document itself is an artifact (object storage
  behind a reference); the database row carries only format, spec
  version, checksum, component count and the artifact reference.
- **Export:** `GET /repositories/:id/sbom` (permission `EXPORT_SBOM`)
  returns the recorded metadata plus the document rebuilt
  deterministically from the snapshot's component rows — the rebuilt
  document and the stored artifact describe the same inventory.
- **Honesty:** an SBOM lists what the manifests declare. Components
  with no declared license show no license; nothing is inferred.
