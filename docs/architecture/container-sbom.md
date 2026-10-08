# Container SBOM (Prompt 34 §52–§55)

SBOMs are produced by the governed Prompt 13 path (Syft) and stored
on the Prompt 12/30 subsystem (`SoftwareBillOfMaterials` /
`SoftwareComponent`) — Prompt 34 deliberately creates NO duplicate
component model. `GET /container/images/:id/sbom` delegates to that
subsystem.

Rules that hold across V1+V2:

- Supported formats: SPDX and CycloneDX (§53).
- Component identity stays name-based with per-field provenance
  (Prompt 30): a name match against vulnerability intelligence
  neither confirms nor clears a vulnerability.
- A component without a known version is UNKNOWN_VERSION, never
  "safe" (§55).
- SBOM coverage is a first-class coverage metric (§113): images
  without an SBOM are a gap, reported as such.
- License data is informational (§54).

Verification (§122): a fixed image is verified by a NEW digest, a
NEW SBOM and a rescan — never by a tag change.
