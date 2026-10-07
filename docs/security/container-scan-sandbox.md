# Container Scan Sandbox (Prompt 13 §9/§10)

Image and manifest analysis runs on the dedicated `CONTAINER_ANALYSIS`
worker type, isolated from web/network/source workers.

## Guarantees

- **Images are never executed.** No `docker run`, no ENTRYPOINT/CMD
  invocation, no script from image content, no package installation
  from an image. A test fixture whose image metadata declares a
  malicious entrypoint proves the entrypoint string never appears in
  any recorded tool invocation — analysis reads config and layers as
  data.
- **Tools run NO_NETWORK.** Vulnerability databases, template packs and
  rule packs are provisioned on the worker out of band (Trivy runs
  with `--skip-db-update --offline-scan`); a scan cannot reach a
  registry, a cluster, or the internet.
- **Manifests are hostile input (§49).** YAML is parsed with the
  JSON schema only — custom tags (e.g. `!!evil`) are rejected, never
  constructed; document count, byte size, node count and depth are
  capped; alias-expansion bombs fail closed.
- **Budgets are clamped in code (§81):** images, image size, packages,
  manifest files, cluster resources, namespaces, cluster requests,
  runtime events and scan duration all have hard caps that client
  input can only lower, never raise.
- **Secrets are metadata only (§18/§40 discipline):** values detected
  in image config/history/manifests are fingerprinted one-way in
  memory and dropped at parse time; they exist in no table, event,
  artifact or API response.
