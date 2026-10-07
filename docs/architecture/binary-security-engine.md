# Binary Security Engine (Prompt 18)

The binary security engine assesses **authorized binary artifacts** with
static analysis only. An artifact's identity is its **SHA-256** (§3); the
same hash in a workspace is the same physical artifact, with tenant
references preserved. Formats (ELF, PE, Mach-O — thin and fat — shared
libraries, object files, DEX-adjacent native artifacts) are identified
from **magic bytes, never file extensions** (§5); unknown content stays
`UNKNOWN` and is never guessed.

## Pipeline

```
registered BinaryArtifact
  → BINARY_ARTIFACT_INTAKE     (identity + intake verdict)
  → BINARY_METADATA_EXTRACTION (platform parsing: headers, sections,
                                hardening, strings, secrets, crypto,
                                dependencies — pure parsing)
  → BINARY_HARDENING_ANALYSIS  (checksec)
  → BINARY_STATIC_ANALYSIS     (Ghidra headless, radare2 typed profiles)
  → DEPENDENCY_INVENTORY / SBOM_GENERATION (components bound to artifact)
  → NORMALIZATION → CORRELATION → RISK_ANALYSIS → QUALITY_GATE → REPORT
  → BINARY_DEBUG_SESSION       (governed LAB evaluation, debug profiles)
```

Six profiles: `BINARY_METADATA_ONLY`, `BINARY_BASELINE`,
`BINARY_ASSESSMENT`, `BINARY_COMPREHENSIVE_STATIC`,
`BINARY_DEPENDENCY_ANALYSIS`, `BINARY_CONTROLLED_DEBUG`.

## Safety invariants

- **Binaries are never executed** — not run, not loaded, not debugged
  live, not emulated, not detonated (§8/§100). A fixture binary whose
  embedded payload would create a marker file if run is analyzed in the
  test-suite; the marker never appears.
- Static adapters run only on `BINARY_STATIC_ANALYSIS` workers; the
  dynamic lab capability (`BINARY_DYNAMIC_LAB`) is a separate worker
  type and neither environment can grant the other (§10).
- Analysis scripts come from the governed approved set only;
  artifact-supplied scripts/configs are never run (§20/§93).
- Secrets persist as type + location + HMAC **fingerprint** + redacted
  preview (§30, P12 discipline). Raw private-key material is never
  persisted anywhere.
- Extracted URLs/domains are `DISCOVERED_REFERENCE` (§31): never
  authorized, never scope-expanding, never auto-scanned.
- Reachability is an evidence state (`REACHABLE` /
  `POSSIBLY_REACHABLE` / `NOT_OBSERVED` / `UNKNOWN`) — it is never a
  claim of exploitability (§62).

## Data model

`BinaryArtifact`, `BinarySection`, `BinaryHardeningProfile`,
`BinaryFunction`, `BinaryImport`, `BinaryExport`, `BinarySymbol`,
`BinaryString`, `BinaryDependency`, `BinaryCryptoReference`,
`BinaryDiff`, `BinaryDebugSession`, `BinaryCrash`; `Finding`,
`SoftwareComponent` and `SoftwareBillOfMaterials` carry a
`binaryArtifactId` binding. Cross-family provenance is preserved:
native libraries from mobile builds and container images link to the
same artifact records (§50–§52).

## Prohibited automation (§78/§123) — never implemented

Exploit generation, weaponized PoCs, shellcode, ROP chains, malware
creation, payload injection, credential dumping, process injection,
persistence, privilege escalation, sandbox escape, AV/EDR evasion,
destructive binary execution.
