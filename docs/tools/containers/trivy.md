# Trivy

**Adapter:** `TrivyAdapter`, executable `trivy`, capabilities
`IMAGE_VULNERABILITY_SCANNING`, `MISCONFIGURATION_SCANNING`,
`SECRET_SCANNING`, `IMAGE_ANALYSIS`. Classification: STATIC_ANALYSIS.
Worker: `CONTAINER_ANALYSIS`.

Static image/filesystem analysis with three strictly separated scanner
kinds (§15–§18): vulnerabilities keep CVE identity; misconfigurations
map to compliance controls and never borrow a CVE; secrets become
metadata-only findings (one-way fingerprint; the matched value is
hashed in memory and dropped). Runs offline (`--skip-db-update`,
`--offline-scan`) — the vulnerability DB is provisioned on the worker
out of band. The image is analyzed, never executed (§9).

## Health

UNAVAILABLE when the binary is absent from the worker host.
