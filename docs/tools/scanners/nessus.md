# Nessus Professional (Prompt 11 §10–§16)

Commercial network vulnerability scanner — **COMMERCIAL / ADMIN_PROVIDED /
LICENSE_REQUIRED**. DSRclone integrates with an administrator-provided
licensed Nessus environment only; Nessus is never redistributed,
bundled or installed by DSRclone.

- **NOT_CONFIGURED is a product state** (§85): with no instance
  registered, Nessus reports NOT_CONFIGURED in health, tooling and scan
  profiles — never an error, never a fake success, and it never blocks
  the platform, other scanners or reporting.
- **Profiles** (§12): logical NETWORK_BASELINE / NETWORK_STANDARD /
  NETWORK_COMPREHENSIVE map to administrator-approved Nessus policy ids
  in instance config. Users never submit raw policy ids.
- **Targets** (§13): generated server-side from verified target +
  approved scope + CIDR policy. Users never submit raw target lists.
- **Parser** (§15): `.nessus` exports normalize plugin id/name/family,
  host/port/protocol/service, severity, CVSS (version preserved), CVE,
  CWE, solution, references and plugin output. Plugin output is
  untrusted data: sanitized, size-capped, never rendered as markup.
- **Raw artifacts** (§16): original exports are stored as governed
  artifacts with checksum, version and scan linkage; raw access needs
  VIEW_RAW_SCANNER_ARTIFACTS (Owner/Admin) — stronger than ordinary
  finding access.
- **License state** is read from the deployment during health checks and
  shown on the scanner admin page; it is never assumed.
