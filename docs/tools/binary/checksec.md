# checksec (Prompt 18 §15)

Hardening-property checker. Plan: `checksec --format=json
--file=<artifact reference>` in a `NO_NETWORK` container on
`BINARY_STATIC_ANALYSIS` workers.

- Reports NX/PIE/RELRO/canary/FORTIFY (ELF) as observations with
  evidence; PE-only states are `NOT_APPLICABLE` on ELF and vice
  versa (§16).
- Gap findings (`BINARY_NO_NX`, `BINARY_NO_PIE`, `BINARY_NO_RELRO`,
  `BINARY_NO_CANARY`, …) carry CWE-693 and converge with platform /
  Ghidra observations into one canonical finding (§52).
- The artifact is input data — checksec reads headers; nothing runs.
