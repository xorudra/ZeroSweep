# Production Deployment V2 (Prompt 38)

The production deployment model deepens Prompt 25; nothing here
replaces it. Deployment styles (§3–§6): single-node Compose
(`deploy/compose/docker-compose.production.yml`), Docker Swarm,
Kubernetes via Kustomize (`deploy/kubernetes`) or Helm
(`deploy/helm/zerosweep`, now with `values.schema.json`, HPA, PDB and
NetworkPolicy templates), external managed services, and air-gapped
installations using imported signed artifacts. Examples live in
`deploy/examples/`.

Invariants carried from V1 and extended here:

- **Immutable releases (§147).** A release is version + commit + build
  + migration state (`ReleaseMetadata`), published by digest. The
  platform records deployments through the admin plane
  (`PlatformDeployment` rows) so `/admin/platform` always shows what is
  actually running.
- **No direct production mutation (§146).** Database changes happen
  only through the dedicated migrate job; the API never races
  migrations.
- **Fail-fast configuration (§16/§17).** The
  `ProductionConfigurationService` evaluates configuration at boot and
  in `/admin/platform`: grouped violations (§20) block production
  boot; secrets must be references (§23/§24) — plaintext secret-shaped
  values are refused, and violation messages never echo values.
- **Connection budget (§27).** Per-replica pool × planned replicas +
  platform headroom must fit the database connection budget; the
  check runs in the config gate and in capacity planning.
- **Operator safety (§158/§159/§202).** Kill switches (scan starts,
  AI workflows, integration sync, report jobs) and maintenance mode
  are confirmation-gated and audited; the scan-start gate is enforced
  in `OrchestrationService.startScan` before the authorization gate.

## Object storage provisioning — attempt record (local stack)

MinIO on the Docker-less local stack, per the project's self-supply
rule (no external provisioning is assumed):

- **Prompt 25 (2026-10-08):** `dl.min.io` download endpoints returned
  **410 Gone**; the GitHub release asset path returned **404**. Health
  reported object storage down, honestly.
- **Prompt 38 (2026-10-08):** retested — `dl.min.io` still **410** on
  every path (latest pointer, .deb package, archive releases
  2025-04-22 and 2024-12-18, direct versioned file); the latest GitHub
  release (RELEASE.2025-10-15T17-29-55Z) ships **no binary assets**
  (source only); no pip package provides a MinIO server.
- **Route that worked:** build the official source tarball
  (codeload.github.com tag archive) with the official Go toolchain
  (go1.27.1 from go.dev). First attempt died on the 512MB /tmp tmpfs
  (Go build work dir); retry with `GOTMPDIR` on the workspace volume
  succeeded. The server runs on 127.0.0.1:9000 (console 9001) with
  local-only generated credentials, started by
  `scripts/local-stack/start.sh`, and the shipped `S3ObjectStore`
  (worker, SigV4) round-trips artifacts against it
  (`scripts/local-stack/minio-smoke.mjs`).
