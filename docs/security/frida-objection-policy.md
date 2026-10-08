# Frida / Objection Policy (Prompt 35 §78–§84)

- **Frida** is a defensive adapter over a **script registry**
  (§80): every script carries id, version, purpose, platform, risk
  class, SHA-256 hash and review status. Only APPROVED entries may
  run, and only inside an approved dynamic session on an authorized
  device. Inline/arbitrary script bodies are not a request shape —
  submitting one is refused and audited (§79/§152).
- Approved module purposes (§81): runtime method observation,
  crypto API observation, secure-storage verification, network-stack
  observation, and test-environment pinning verification (§82 —
  observation of a test app's controls, never a generic bypass
  service for third-party apps).
- **Objection** exposes only the approved defensive workflows (§83):
  app storage inventory, keychain class observation, root-detection
  behaviour check, SSL-pinning behaviour check, environment
  inventory. Arbitrary interactive device commands are never exposed
  through the web UI (§84).
- Runtime instrumentation requires the separate high-risk
  permission `RUN_APPROVED_RUNTIME_INSTRUMENTATION` (§135).
