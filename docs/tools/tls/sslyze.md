# SSLyze — independent TLS + certificate analysis

**Slug:** `sslyze` · **Category:** WEB · **Risk:** LOW · **Parser:** `sslyze-json`

## Purpose

A second, independent implementation of TLS analysis whose primary job in
ZeroSweep is **corroboration**: when SSLyze and testssl.sh agree that a
service offers TLS 1.0, the merged canonical finding's confidence rises —
because two independent codebases observed the same fact, not because
one signature was copied twice.

## Checks used

- Protocol cipher-suite acceptance for SSL 2.0/3.0 and TLS 1.0–1.3:
  accepted suites on a deprecated protocol → `TLS_WEAK_PROTOCOL`.
- Certificate info: expired leaf certificate → `TLS_CERTIFICATE_EXPIRED`;
  failed path validation against a trust store →
  `TLS_CERTIFICATE_UNTRUSTED`. A valid, trusted certificate produces no
  finding — silence is a result, not a gap.
- Heartbleed probe result: a positive is reported as its named check
  (CVE-2014-0160 is the identity of that specific check, not a guess).

## Output normalization

SSLyze JSON is deeply nested and version-sensitive; the parser extracts
defensively (missing branches → no finding, malformed JSON → warning).
Service selection follows the same TLS-only, budget-capped rules as
testssl.sh.
