# Syft

**Adapter:** `SyftAdapter`, executable `syft`, capabilities
`SBOM_GENERATION`, `IMAGE_ANALYSIS`. Classification: STATIC_ANALYSIS.
Worker: `CONTAINER_ANALYSIS`.

Generates the package inventory for an image or filesystem (syft-json).
Packages become `SoftwareComponent` rows bound to the image (Package
URL identity); the CycloneDX/SPDX SBOM document is built from that
inventory by the platform SBOM builders (§12–§14). Syft reads package
metadata only — it never executes image content.

## Health

UNAVAILABLE when the binary is absent from the worker host.
