# Mobile Security V2 — Architecture (Prompt 35)

Prompt 35 deepens the Prompt 17 mobile engine and the Prompt 18
binary engine on the SAME canonical records. It adds a governance
layer, not a second pipeline:

- **SDK** `packages/security-sdk/src/mobbin/` — V2 profiles (§15),
  the analysis-plan builder + dynamic gate (§13/§14), ADB / Frida /
  Objection defensive policy (§75–§84), traffic redaction + scope
  (§88–§93), version-lineage carry-forward (§105–§108), coverage
  honesty (§121–§126), contextual Risk V3 signals (§111/§112),
  deterministic NL plans + the defensive AI guard (§129–§132), and
  report definitions (§127/§128).
- **API** `apps/api/src/modules/mobile-binary-v2/` — the §133 route
  shapes. Every write delegates to the governed Prompt 17/18
  services (intake, gated scans, dynamic-session policy, binary
  scans) or persists a governed V2 record (plan, lineage, coverage,
  traffic session). Nothing new executes.
- **Data** — `MobileAnalysisPlan`, `ApplicationVersionLineage`,
  `MobileFindingCarryForward`, `MobileSecurityCoverage`,
  `BinarySecurityCoverage`; `MobileTestDevice` gains the §72 device
  profile (type / ownership / authorization / environment);
  `MobileInstrumentationModule` gains the §80 registry fields
  (purpose / platform).

Pipeline (§14): INGEST → CLASSIFY → STATIC_ANALYSIS →
DEPENDENCY_ANALYSIS → SECRET_ANALYSIS → BINARY_HARDENING →
OPTIONAL_DYNAMIC_ANALYSIS → TRAFFIC_ANALYSIS → NORMALIZATION →
CORRELATION → RISK → REMEDIATION → REPORT. The dynamic stage is
optional and gated; static is the default (§16).

Non-goals (§164) are structural: no artifact is installed, run,
emulated or executed; no arbitrary ADB shell, Frida script or
Objection command exists as a request shape; no exploit generation;
no credential validation against external services; discovered
endpoints never become authorized scope.
