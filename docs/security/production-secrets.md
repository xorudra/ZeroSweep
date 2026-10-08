# Production Secrets (Prompt 38 §21–§29)

- Production secrets are **references**, never values, in every file
  this repository ships: `env:` / `file:` / `docker-secret:` /
  `k8s-secret:` / `vault:` / `aws-sm:` / `gcp-sm:` / `azure-kv:` —
  validated by the SDK (`isSecretReference`) and the production
  config gate. Secret-shaped plaintext is refused at boot.
- Distinct credentials per data service (§26); least-privilege DB
  roles (the API role cannot run migrations; the migrate job's role
  is separate) (§28).
- Rotation (§29): rotate the provider-side credential, update the
  reference target, roll the workload. Backup passphrases are files
  mounted from the secret store (§166), never env values in git.
- Logs, metrics, traces, backups and support bundles exclude secrets
  by construction + redaction layers (§110/§116/§165/§210).
