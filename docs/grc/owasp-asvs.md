# OWASP ASVS 4.0.3 in DSRclone (Prompt 26)

Shipped catalog version: OWASP_ASVS 4.0.3 (V1–V14 chapter
structure). ASVS is open (CC BY-SA); requirement IDs/titles are the
published reference structure.

Mapping notes:

- V2 (authentication) — MFA/session controls; V3 (session) PARTIAL.
- V4 (access control) — RBAC posture evidence PARTIAL.
- V5/V6 (validation & cryptography) — finding classes (input
  validation, crypto) map as evidence; absence of findings is weak
  evidence and lands PARTIALLY_COMPLIANT at best in ASVS roll-ups.
- V7 (error handling/logging) — logging controls.
- V9 (communications) — TLS controls DIRECT for V9.1.
- V10/V12 (malicious code, files) — SAST/SCA evidence PARTIAL.
- V14 (configuration) — security headers/TLS posture PARTIAL.

ASVS verification is a testing discipline performed by assessors;
DSRclone aggregates scanner and platform evidence toward it. **It
does not issue ASVS verification or L1–L3 attestation.**
