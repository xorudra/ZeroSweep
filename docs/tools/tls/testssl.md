# testssl.sh — TLS configuration assessment

**Slug:** `testssl` · **Category:** WEB · **Risk:** LOW · **Parser:** `testssl-json`

## Purpose

TLS protocol support, cipher strength, certificate validity and TLS
hardening (HSTS and friends) for the target's TLS services.

## Service selection

testssl.sh runs ONLY against TLS services: HTTPS endpoints or detected
TLS services produced by earlier stages (`host:port` stage inputs),
capped by the budget's `maxTlsServices`. It never scans "every port",
and redirect destinations are re-checked against scope — a redirect
never drags a TLS scan to a third-party host.

## Output normalization

The JSON findings array is classified by check id + severity:

- `OK` / `INFO` severities → **configuration observations** (e.g.
  "SSLv3 not offered"), recorded in metrics, never promoted to findings.
- Weak/deprecated protocols → `TLS_WEAK_PROTOCOL`; weak ciphers →
  `TLS_WEAK_CIPHER` (source-supplied CWE is carried when testssl
  provides it); expired certificates → `TLS_CERTIFICATE_EXPIRED`;
  missing HSTS → `MISSING_SECURITY_HEADERS`.
- CVE/CVSS appear only when the testssl record itself provides them.

testssl findings are designed to correlate with SSLyze's independent
view of the same service — see `docs/architecture/finding-pipeline.md`.
