# Container Hardening (Prompt 38 §7–§15)

- One image per service/pool (§7); scanner pools use
  `deploy/docker/scanner-worker.Dockerfile` layers carrying only their
  pool's tools.
- Non-root users, read-only root filesystems, `cap_drop: [ALL]`,
  `no-new-privileges`, seccomp `RuntimeDefault`, bounded tmpfs and
  CPU/memory/ephemeral-storage limits (§11–§14) — see the hardened
  compose profiles and Helm/Kustomize pod specs.
- No Docker socket is mounted anywhere in this repository — a test
  asserts it (§15). No privileged containers.
- Images are scanned in CI (Trivy gate on CRITICAL/HIGH) and released
  by digest with an SBOM (§143/§144).
