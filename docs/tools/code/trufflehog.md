# TruffleHog

**Adapter:** `TrufflehogAdapter`, executable `trufflehog`,
capabilities `SECRET_DETECTION`, `SECRET_VERIFICATION`. Risk:
PASSIVE. Worker: `SOURCE_ANALYSIS`.

Secret scanning (filesystem + git history) with detector-level
classification. **External verification is disabled by default and
pinned off in every worker-built plan** (`--no-verification`); a
configuration requesting it is rejected outright (§37/§44) — the
platform does not probe third-party services with discovered
credentials. Findings merge with Gitleaks' by secret fingerprint.

## Health

UNAVAILABLE when the binary is absent from the worker host.
