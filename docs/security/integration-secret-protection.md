# Integration Secret Protection (Prompt 24 §101–§102)

Credential values never enter the platform:

- Integrations, cloud-style configs and webhook subscriptions store
  only secret **references** (`env:NAME`, secret-manager references).
  The `Integration` model has no credential column.
- Configuration schemas reject secret-shaped values anywhere (token
  prefixes, private keys, credential assignments) — a paste mistake
  fails validation instead of persisting a secret.
- The API `present()` shape exposes `secretConfigured`,
  `secretReference` and `secretRotatedAt` only. UI pages render the
  same fields. **Secret values never appear in UI, API output, logs,
  tickets, reports or events.**
- Rotation replaces the reference and stamps the rotation time; no
  step of rotation ever handles a value.
- A reference is resolved only at the moment of use (webhook
  verification, outbound signing, connector auth) by the
  environment-backed resolver; resolution failures report as
  NOT_CONFIGURED, never as a leaked default.
