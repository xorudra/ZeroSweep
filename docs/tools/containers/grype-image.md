# Grype (image inputs)

**Adapter:** the Prompt 12 `GrypeAdapter` (see `docs/tools/code/grype.md`),
extended in place per §19 — never duplicated. Capabilities add
`IMAGE_VULNERABILITY_SCANNING`; supported targets add `CONTAINER_IMAGE`.
Worker: `CONTAINER_ANALYSIS` for image inputs.

With an image reference (worker-derived from the registered image +
resolved digest), Grype scans the image instead of a source directory
and its matches normalize through the shared image-vulnerability
fingerprint, so a CVE reported by both Grype and Trivy for the same
package+version+digest correlates into ONE canonical finding with two
observations (§20).

## Health

UNAVAILABLE when the binary is absent from the worker host.
