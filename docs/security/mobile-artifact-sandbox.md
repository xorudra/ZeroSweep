# Mobile Artifact Sandbox (Prompt 17 §7/§8/§107)

Application packages are **hostile content**. The sandbox rules:

## Intake validation

- Format is sniffed from content (APK/AAB/IPA/DEX zip family), never
  trusted from the file name.
- The artifact's SHA-256 is its identity; a client-declared hash
  must match when provided, and a build cannot be registered without
  a trustworthy hash.
- Archive entries are validated before parsing: traversal (`..`),
  absolute paths, drive paths, backslash separators, symlinks and
  hardlinks are refused; entry count, per-entry size, total size
  and compression ratio (zip-bomb) are capped by the mobile budget
  (§91).
- Signing metadata keys that look like key material
  (private/secret/password/keystore) are dropped at the API — keys
  are never stored; references only.

## Analysis sandbox

- Static workers (`MOBILE_STATIC_ANALYSIS`) run adapters with
  **no network**; artifacts are extracted into the safe workspace
  with the Prompt 12 discipline.
- App code is **never executed**: no install, no emulation, no
  instrumentation during static analysis. Decompiled code is data.
- Extracted artifacts are sensitive: access requires
  `VIEW_MOBILE_SOURCE_ARTIFACTS` and is audited per access (§24).
- All strings from artifacts are sanitized and rendered as inert
  text in the UI — hostile manifest/plist strings cannot inject
  (§108). Secret values found in artifacts are redacted before
  anything is persisted (§28).
