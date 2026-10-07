# Container Security (Prompt 13)

Container images are first-class assets (`CONTAINER_IMAGE` targets plus a
`ContainerImage` inventory). The governing rule is §9: **images are never
executed**. No code path in DSRclone runs an image, invokes its ENTRYPOINT
or CMD, executes a script from it, or mounts a Docker socket to reach it.
Analysis is static: image configuration, layer metadata, package
inventories and scanner databases, all read by governed adapters on the
isolated `CONTAINER_ANALYSIS` worker type.

## Identity and drift (§5, §78)

An image's strongest identity is its **digest**. Registration parses the
reference (`registry/repository[:tag][@digest]`); the `IMAGE_RESOLUTION`
platform stage records a `ContainerImageSnapshot` for every scan, binding
the scan's findings to the digest in force. When a tag later resolves to a
different digest, the snapshot records `drift` with the previous digest —
history is appended, never overwritten.

## Toolchain (§12–§24)

- **Syft** generates the package inventory → `SoftwareComponent` rows bound
  to the image; the CycloneDX SBOM document is built on demand from that
  inventory (reference + checksum persisted, document is an artifact).
- **Trivy** runs three strictly separated scanner kinds: vulnerabilities
  (CVE identity), misconfigurations (control identity — never a CVE), and
  secrets (metadata + one-way fingerprint only, §18; the matched value is
  hashed in memory and dropped).
- **Grype** is the Prompt 12 adapter extended in place (§19): the same
  adapter takes a source snapshot or an image reference. When Trivy and
  Grype report the same CVE for the same package+version on the same
  digest, correlation merges them into ONE canonical finding with two
  scanner observations (§20).
- OS packages and language packages are distinguished (`packageType`), and
  fixed versions appear only when the scanner data carries them (§24).

## Profiles

`CONTAINER_BASELINE`, `CONTAINER_COMPREHENSIVE`, `SBOM_ONLY`,
`IMAGE_VULNERABILITIES_ONLY`, `CONTAINER_MISCONFIG_ONLY` and the legacy
`CONTAINER` alias resolve over: IMAGE_RESOLUTION → SBOM_GENERATION (Syft)
→ IMAGE_VULNERABILITY_SCAN (Trivy/Grype) → MANIFEST_SCAN → NORMALIZATION →
CORRELATION → RISK_ANALYSIS → QUALITY_GATE → REPORT_GENERATION. The
container quality gate (§75) fails on KEV-listed image CVEs (from the
Prompt 11 governed dataset only), critical image CVEs, verified image
secrets and privileged-container misconfigurations; the deployment gate
(§76) reports a verdict — DSRclone itself never deploys or blocks a
production system.

## Docker host posture (§27–§31)

Docker Bench for Security is classified `INTERNAL_PRIVILEGED`: it is
selected for `DOCKER_HOST` targets, but the worker executor refuses it
unless the worker carries the `PRIVILEGED_HOST_ASSESSMENT` capability,
which only a worker of type `PRIVILEGED_HOST` can hold. Benchmark results
normalize to CIS Docker control assessments; FAIL/WARN raise findings,
PASS is recorded as evidence only.
