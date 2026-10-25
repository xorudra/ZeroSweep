# Android Security Analysis (Prompt 17)

## Intake

APK (and AAB-derived) artifacts enter through the hostile-content
intake (`docs/security/mobile-artifact-sandbox.md`): magic sniffing,
SHA-256 identity, hostile archive validation (traversal, absolute
paths, symlinks, zip bombs, entry/size caps) before anything is
parsed.

## Manifest analysis (§18/§20/§21)

From `AndroidManifest.xml` (apktool decode or recorded output):

- package, version name/code, min/target SDK;
- permissions inventoried and classified
  normal / dangerous / signature / custom;
- activities, services, receivers, providers inventoried with
  `exported` state and their guarding permission — an exported
  component without a permission is a finding only when the
  component class makes it sensitive (content providers, file
  providers, deep-link handlers); otherwise it is inventory;
- deep links (scheme/host/pathPrefix, `autoVerify`) inventoried —
  presence alone is not a vulnerability;
- `debuggable`, `allowBackup`, cleartext flags as posture rules.

## Network security config (§23)

`usesCleartextTraffic` and `networkSecurityConfig` domain rules are
evidence for `MOBILE_CLEARTEXT_ENABLED`; user-added CA trust is
inventoried; certificate pinning presence is recorded as an
observation — ZeroSweep never bypasses pinning automatically.

## Code analysis (§19/§27/§28)

JADX decompilation output is an analysis artifact; it is never
executed and access is RBAC-gated (`VIEW_MOBILE_SOURCE_ARTIFACTS`,
audited per access). Source snippets feed endpoint extraction and
secret detection. Secrets are stored as **type + location + HMAC
fingerprint + redacted preview only** — raw values are never
persisted, logged or displayed (Prompt 12 discipline).

## Rules (canonical IDs)

`MOBILE_CLEARTEXT_ENABLED`, `MOBILE_EXPORTED_COMPONENT_UNPROTECTED`,
`MOBILE_DEBUGGABLE_BUILD`, `MOBILE_BACKUP_ALLOWED`,
`MOBILE_HARDCODED_SECRET`, `MOBILE_WEAK_CRYPTOGRAPHY`,
`MOBILE_INSECURE_RANDOM`, `MOBILE_WEBVIEW_JS_BRIDGE`,
`MOBILE_WEBVIEW_FILE_ACCESS`, `MOBILE_SENSITIVE_DATA_LOGGING`,
`MOBILE_WORLD_READABLE_STORAGE` — each mapped to OWASP Mobile Top 10
(2024) and, where reliable, MASVS v2.1. No formal MASVS
certification is ever claimed (§48).

MobSF / JADX / apktool / platform observations of the same issue
deduplicate into one canonical finding (§50).
