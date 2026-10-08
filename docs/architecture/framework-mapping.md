# Framework Mapping (Prompt 26 §3–§12)

Frameworks are **versioned reference data**: `ComplianceFramework`
(key + version, status DRAFT/ACTIVE/DEPRECATED/RETIRED) owns a
hierarchy of `ComplianceRequirement` rows. Published versions are
immutable — importing an existing (key, version) is refused, a new
edition is a new row, and existing assessments keep pointing at the
version they were created against (§4/§122).

## Cross-framework mapping

One internal `SecurityControl` maps to many requirements across
frameworks via `ControlFrameworkMapping`
(control ↔ requirement, mapping type, coverage 0..1, notes, source).
The MFA control, for example, maps DIRECT to PCI DSS 8.4, PARTIAL to
NIST SP 800-53 IA-2 and SUPPORTING to ISO/IEC 27001 A.5.17 — the same
collected evidence serves every mapped requirement without
duplication (§12/§123).

## Honesty rules

- Mapping types are DIRECT / PARTIAL / SUPPORTING (§10).
- A requirement computes COMPLIANT **only** when substantive
  (DIRECT/PARTIAL) mappings with combined coverage ≥ 1 all PASS on
  current, usable evidence — or an accepted manual review covers the
  remainder. Partial technical support of an administrative
  requirement yields at best PARTIALLY_COMPLIANT (§11/§124).
- SUPPORTING mappings alone never establish compliance.
- Results are assessment states (COMPLIANT / PARTIALLY_COMPLIANT /
  NON_COMPLIANT / NOT_APPLICABLE / NOT_ASSESSED), not certification
  claims (§37).
