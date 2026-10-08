# OpenVAS / Greenbone Integration (Prompt 33 §56/§57)

The Greenbone/OpenVAS integration is the Prompt 11 connector — V2 uses
it unchanged:

- **Lifecycle**: target creation → task creation → status → result
  import → report import → cleanup, through the governed GMP
  connector. Reports are parsed by the Prompt 11 Greenbone parser
  (hostile-input discipline: size caps, DOCTYPE/ENTITY rejection,
  field caps, sanitization) into NormalizedVulnFindings, then V2
  normalization adds plugin provenance (NVT OID, family, feed context)
  and network correlation keys.
- **Profiles**: DSRclone profiles map to administrator-configured
  Greenbone scan configurations via logical profiles (BASELINE /
  STANDARD / COMPREHENSIVE). Arbitrary scanner settings are never
  exposed through the platform.
- **Health**: unconfigured instances report NOT_CONFIGURED; a scan
  whose Greenbone leg fails is PARTIAL with the gap recorded — never
  "no vulnerabilities" (§155).
- **Credentials**: instance credentials are secret references resolved
  by the connector; they never appear in logs, findings or reports.
