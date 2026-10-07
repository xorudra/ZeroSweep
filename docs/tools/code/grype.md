# Grype

**Adapter:** `GrypeAdapter`, executable `grype`, capabilities
`PACKAGE_VULNERABILITY_ANALYSIS`, `SBOM_ANALYSIS`. Risk: PASSIVE.
Worker: `SOURCE_ANALYSIS`.

Package vulnerability scanning over the snapshot directory (or an
SBOM input). JSON output; a fixed version is carried only when Grype
reports the vulnerability state as `fixed` (§74). Grype can also be
selected as the SBOM source for the inventory merge; component
identity is always the Package URL (§46).

## Health

UNAVAILABLE when the binary is absent from the worker host.
