# Release Management — ZeroSweep (§143–§152)

## Versioning & artifacts

- Versions are semantic per release train (`25.0.0`); image tags equal
  the version and are IMMUTABLE — a tag is never re-pushed with different
  content. Hotfixes get a new patch version.
- Every release produces `release-manifest.json`
  (`deploy/scripts/release-manifest.mjs`): version, git commit, image
  references + digests (supplied by the build system), SBOM references,
  migration head, worker version, and the governed tool-inventory count.
- **Drift detection (§145)**: differing worker versions or tool-inventory
  counts between environments flag an unrecorded change — investigate
  before promoting further.

## Security gate (§18)

Trivy/Grype scan (fail on fixable CRITICAL), Syft SBOM, cosign signing.
Admission (deploy/policies) verifies signatures in production and rejects
unsigned images.

## Change classes

- **Code-only**: standard rollout per the deployment runbook.
- **Expand migration**: rollout safe in any order (migration Job first by
  default).
- **Contract migration**: requires a change record proving all replicas
  run post-migration code; scheduled in a maintenance window.
- **Policy change** (ScannerCapabilityPolicy, admission policies):
  security review required; never bundled silently with feature releases.

## Rollback

Per the deployment runbook: re-apply the previous manifest's digests.
Data-affecting failures escalate to restore — never reverse DDL.
