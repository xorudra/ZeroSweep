# Ghidra (Prompt 18 §18–§21)

Headless static analysis via `analyzeHeadless`, extended in Prompt 18
from the Prompt 17 mobile adapter (one dual-mode adapter owns the
`ghidra` slug; mobile configurations delegate unchanged).

- Plan: `BinarySandbox/BinaryInventory` project, `-import <artifact
  reference>`, `-scriptPath /opt/zerosweep/ghidra-scripts`,
  `-postScript BinarySecurityInventory.py`, `-deleteProject`. The
  script is pinned by the platform from the administrator-approved
  set — script selection is never configuration, and user-supplied
  Ghidra scripts are never accepted (§93).
- Output: a bounded JSON inventory (program, sections, functions with
  stable fingerprints, imports/exports/symbols, libraries, hardening)
  parsed by `parseBinaryGhidraReport`; hostile/oversized output is
  bounded and sanitized before use.
- Runs only on `BINARY_STATIC_ANALYSIS` workers (or
  `MOBILE_STATIC_ANALYSIS` for mobile profiles), `NO_NETWORK`,
  timeout-bounded. The artifact is imported as data — never executed.
