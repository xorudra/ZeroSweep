# Mobile Artifact Sandboxing (Prompt 35 §9–§12/§164)

Every uploaded APK/AAB/IPA/binary is untrusted input (§11).

- **Upload** (§9): authentication, RBAC (`UPLOAD_MOBILE_ARTIFACT`),
  workspace ownership, size limit, file-type + content-type
  validation, SHA-256 hashing (§8: identity is the hash, never the
  filename), object-storage isolation.
- **Archive safety** (§10): zip bombs, path traversal (zip-slip),
  oversized extraction, symlink abuse and malformed archives are
  refused at intake by the Prompt 17 validator — the pre-read
  central directory is checked before any extraction exists.
- **Sandbox** (§12): analysis runs in isolated scanner workers.
  Untrusted binaries are never analyzed in the API/web process, and
  never installed, run, emulated or executed anywhere (§164).
- **Persistence discipline**: metadata + bounded extracted
  artifacts only, sanitized value-by-value and secret-redacted
  before storage (see `mobile-secret-redaction.md`). Raw artifact
  bytes live in object storage behind a reference, never in
  Postgres rows.
