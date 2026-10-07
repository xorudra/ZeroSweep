# OWASP Dependency-Check

**Adapter:** `DependencyCheckAdapter`, executable
`dependency-check`, capability `DEPENDENCY_VULNERABILITY_ANALYSIS`.
Risk: PASSIVE. Worker: `SOURCE_ANALYSIS`.

Dependency vulnerability analysis over the snapshot's manifests.
Every network-touching feature is pinned off in the plan (hosted
suppressions, OSS Index, retire.js and bundle-audit updates disabled)
— analysis runs against local data only. CVE/CVSS data from its
report is treated as scanner observation; the platform's canonical
matching still runs against the governed local intelligence dataset
(Prompt 11), and duplicates with Grype merge per CVE+component (§58).

## Health

UNAVAILABLE when the binary is absent from the worker host.
