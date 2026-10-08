# Binary Security (Prompt 35 §51–§70)

The binary pipeline is Prompt 18's, deepened by Prompt 35 coverage
(§123) and lineage. Artifacts (§51) are registered by SHA-256 with
format (ELF / PE / MACH_O / DEX / OTHER_SUPPORTED), architecture,
endianness and bitness from safe parsers (§52/§53).

- **Hardening** (§54/§55): checksec-class evidence — NX, PIE, RELRO,
  stack canary, FORTIFY. Missing hardening is contextual and never
  auto-critical.
- **Inventory** (§56–§58): imports/exports and strings are bounded;
  millions of strings are never dumped into the database.
- **Ghidra** (§59/§60): headless analysis in an isolated worker
  with timeout, memory, disk and output limits. A budget overrun
  ends partial/error — safely (§148).
- **radare2 / Cutter** (§61): metadata, functions, imports, strings,
  cross references.
- **Binary Ninja / IDA** (§62–§64): optional, license-detected
  connectors (Prompt 18 posture: NOT_CONFIGURED when no licensed
  installation exists). Unavailability marks the capability, never
  fails the pipeline (§149).
- **Rules** (§65/§66): `BinarySecurityRuleEngine` categories —
  unsafe-function indicators, hardcoded secrets, debug artifacts,
  insecure hardening, suspicious configuration, dependency risk.
  Function/import presence alone is not proof of exploitability.
- **GDB / pwndbg** (§67–§69): governed LAB debug records only
  (Prompt 18 debug policy: separation of duties, approved sessions,
  transport NOT_PROVISIONED in this environment). Debugging never
  runs on the API process.
- **No exploit generation** (§70): no ROP chains, shellcode,
  weaponized payloads or persistence — by construction, not by
  filter.
