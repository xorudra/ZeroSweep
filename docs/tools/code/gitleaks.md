# Gitleaks

**Adapter:** `GitleaksAdapter`, executable `gitleaks`, capability
`SECRET_DETECTION`. Risk: PASSIVE. Worker: `SOURCE_ANALYSIS`.

Secret scanning over the working tree and bounded git history
(depth from the source scan budget, §83). Matches become secret
findings: the matched value is consumed once by the fingerprint
service at parse time and dropped — persisted rows hold type,
detector, file/line, fingerprint and redacted preview only (§40).

## Health

UNAVAILABLE when the binary is absent from the worker host.
