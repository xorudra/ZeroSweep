# Binary Analysis Pipeline (Prompt 18)

## Stages and producers

| Stage | Producer | Output |
| --- | --- | --- |
| `BINARY_ARTIFACT_INTAKE` | platform | intake verdict (registered artifact required, else the scan fails honestly as NOT_CONFIGURED) |
| `BINARY_METADATA_EXTRACTION` | platform parser | header report, sections, hardening signals, bounded strings, secret candidates (fingerprint only), crypto references, dependency inventory |
| `BINARY_HARDENING_ANALYSIS` | checksec | hardening observations + gap findings |
| `BINARY_STATIC_ANALYSIS` | Ghidra (headless, approved script), radare2 (typed profile) | function/import/export/symbol inventories, risky-API reference evidence |
| `DEPENDENCY_INVENTORY` | platform | persisted dependency/component counts |
| `SBOM_GENERATION` | platform | CycloneDX + SPDX documents bound to the artifact (reference + checksum persisted) |

## Parsing discipline

Header parsers (ELF program/section headers, PE COFF/optional header +
data directories, Mach-O load commands incl. fat binaries) are
**fail-safe**: malformed fixtures produce a report with errors, never a
throw, never a guess. String extraction is bounded (count + byte caps),
classifies into URL/DOMAIN/FILE_PATH/REGISTRY_PATH/DEBUG_STRING/
ERROR_MESSAGE/CRYPTO_REFERENCE/SECRET_CANDIDATE/GENERIC, and secret
candidates leave the extractor only as fingerprint + redacted preview.

## Correlation (§50–§52)

Findings are stamped with the §57 binary fingerprint
(`lineage | component | rule | CWE | class | location`, where lineage is
`format:architecture:artifactName` — deliberately excluding the artifact
hash so fingerprints are cross-build). Observations of the same root
cause from checksec, the platform parser, Ghidra and radare2 converge
to **one canonical finding** with all sources preserved. Dependency
findings keep their PURL + CVE identity.

## Risk (§56–§63)

Risk Engine V2 consumes binary findings with `staticConfidence` bands
and reachability evidence states. The quality gate fails on any
Critical binary finding, any embedded-secret finding, or any KEV-listed
dependency finding. Static conclusions are labelled as static —
dynamic validation outcomes stay separate (§81).

## Retesting

Binary retests are artifact-over-artifact: `planBinaryRetest` maps a
finding back to its original stage family/tool, the child scan runs
against the target's current artifact, and judgement compares §57
fingerprints. A retest that cannot run is FAILED, never a pass.
