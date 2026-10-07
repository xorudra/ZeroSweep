# Binary Artifact Protection (Prompt 18 §6/§30/§84)

- **Identity**: artifacts are identified by SHA-256 (SHA-1 kept only
  for interoperability). Registration dedupes by `(workspaceId,
  sha256)`; tenant references to the same physical artifact are
  preserved.
- **Intake**: size caps, digest-shape validation, magic-byte format
  identification (a spoofed name is reported as the real format), and
  the hostile-archive discipline for firmware inventories (zip-slip,
  symlink escape, bomb caps). Only metadata + a bounded header segment
  (≤ 1 MiB) + sanitized recorded outputs are registered — never raw
  executable content in API payloads.
- **Secrets**: anything secret-shaped found in an artifact persists
  as type + location + HMAC fingerprint + redacted preview. Full
  values — and private-key material in any form — exist in **no**
  database row, API response, log or report (tests prove absence of
  the planted fixture token across all persisted records).
- **Access**: raw artifact record reads are audited every time
  (`BINARY_ARTIFACT_ACCESSED`, §84); the function/decompilation
  explorer is separately permission-gated (`VIEW_BINARY_DECOMPILATION`)
  and audited (`BINARY_DECOMPILATION_ACCESSED`).
- **Scope**: extracted URLs/domains/IPs are `DISCOVERED_REFERENCE`
  (§31) — inventory for review, never authorization, never scope
  expansion, never auto-scanned.
- **Tenant isolation**: every read is workspace-scoped; cross-tenant
  access returns NOT_FOUND (§119, tested).
