# Source Code Security Engine (Prompt 12)

Repositories are first-class targets (`SOURCE_REPOSITORY`) whose content
is **hostile input**: it is acquired into immutable snapshots, analyzed
read-only by governed tool adapters, and never executed. The engine adds
SAST, secret scanning, dependency analysis (SCA) and SBOM generation on
top of the existing foundations — the Tool Adapter SDK (Prompt 3), the
scan DAG (Prompt 4), the findings pipeline (Prompt 7) and the governed
intelligence dataset (Prompt 11).

## Acquisition and snapshots (§6–§14)

A repository is registered one of three ways: an approved **git remote**
(SSRF-guarded URL intake — metadata/loopback/private destinations are
blocked unless an internal engagement explicitly allows them; embedded
credentials are rejected; credentials exist only as reference names), an
**uploaded archive**, or a **workspace snapshot manifest** (file listing +
manifest file contents registered as data). Every path in an archive or
manifest is validated as a safe repository-relative path; archive
extraction (where a worker supports it) rejects traversal (zip-slip),
symlink escapes, decompression bombs and excessive file counts.

Scans operate on an immutable **SourceSnapshot**: content hash, commit,
branch, file listing and manifest contents. Acquisition is a DAG stage —
when no snapshot can be materialized (e.g. a git remote whose clone has
not been provisioned on a source worker) the stage fails honestly
(`SOURCE_SNAPSHOT_UNAVAILABLE`) instead of inventing content.

## Pipeline (§18/§19)

`AUTHORIZATION_CHECK → SCOPE_VALIDATION → SOURCE_ACQUISITION →
LANGUAGE_DETECTION → SAST → SECRET_SCANNING → DEPENDENCY_ANALYSIS →
SBOM_GENERATION → NORMALIZATION → CORRELATION → RISK_ANALYSIS →
QUALITY_GATE → REPORT_GENERATION`

Profiles: `SOURCE_BASELINE` (curated SAST set + both secret scanners +
Grype), `SOURCE_COMPREHENSIVE`, `SECRETS_ONLY`, `DEPENDENCIES_ONLY`,
`SAST_ONLY`. `CODE_ASSESSMENT` (Prompt 4) maps to the baseline chain.
Language/framework/build detection is metadata-only classification over
the snapshot's listing and manifests (§27).

## Safety invariants

- **No code execution, ever** (§15/§30): the execution policy defaults
  to `DO_NOT_EXECUTE_SOURCE`. No build scripts, package-manager
  lifecycle hooks, git hooks or target test runs execute anywhere in
  the pipeline; git operations disable hooks and credential helpers.
  Cases that would need a build (e.g. CodeQL for compiled languages
  without a no-build mode) end as `BUILD_REQUIRED`, never a build.
- **Secrets are metadata only** (§40): findings carry type, detector,
  file/line, a one-way fingerprint and a redacted preview. The raw value
  is consumed by the fingerprint function at parse time and dropped.
- **Findings are normalized** into the common pipeline with
  repository-relative locations and line-stable fingerprints (§59/§64),
  so the same flaw merges across tools and across snapshots (baselines:
  NEW / EXISTING / RESOLVED, §79).
- **SCA matches only the governed local dataset** (Prompt 11): an empty
  dataset yields zero matches, shown honestly; CPE→CVE links are
  `POTENTIAL_EXPOSURE`, never confirmed vulnerabilities (§73).
- The **quality gate** (PASSED / FAILED / WARNING) is evaluated from
  deterministic counts and recorded per scan; it never rewrites the
  scan's own status (§82).

## Surfaces

API: `/repositories` CRUD + verify + scans, snapshots / findings /
secrets / dependencies / sbom subroutes, `/source-scans/:id/quality-gate`
(§97), behind the §98 permission set. GUI: `/code-security` dashboard +
repository table, `/code-security/repositories/[id]` detail (snapshot,
findings, secret dashboard, dependency dashboard, SBOM), and a
code-location panel on the finding detail page (§89–§95).
