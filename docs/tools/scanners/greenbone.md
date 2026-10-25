# Greenbone / OpenVAS (Prompt 11 §3–§9)

Open-source network vulnerability scanner, integrated as an
administrator-managed connector (`greenbone-openvas`).

- **Instances** are admin-registered (Settings → Scanners): endpoint
  REFERENCE + credential REFERENCE names only — never URLs or secret
  values. Instance `config` holds the logical-profile mappings and the
  last reported feed state.
- **Health** (§5): HEALTHY / DEGRADED (reachable but feed stale) /
  MISCONFIGURED (endpoint reference unresolved) / UNAVAILABLE. Feed
  status is part of health, not an afterthought.
- **Profiles** (§7): users select LOGICAL profiles — BASELINE, STANDARD,
  COMPREHENSIVE. The mapping to real Greenbone scan-config ids lives in
  administrator instance configuration. Unmapped profile → scan creation
  is refused.
- **Targets** (§6): generated server-side from verified ZeroSweep scope
  (include hosts/CIDRs, exclusions win, wildcards rejected, bounded).
  Raw target lists from clients are never forwarded.
- **Tasks**: create → poll (bounded, cancellable) → fetch report →
  `GreenboneFindingParser` (NVT OID, CVSS, CVE from NVT metadata) →
  normalize → correlate. When Greenbone is unavailable, dependent stages
  end SKIPPED/DEGRADED — unrelated scans never crash (§86).
- **Fallbacks**: Greenbone results can be imported from report exports
  through the same preview/commit import flow as Nessus.
