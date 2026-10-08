# Patch Intelligence (Prompt 30 §40–§45, §84–§86)

- `SecurityAdvisory` deduplicates by (provider, advisoryId) (§44); advisories derive `PatchRecord`s keyed by (cveId, productKey, source) — the fixed version exactly as that source states it (§41/§85).
- CVE-level patch status (`assessPatchStatus`): `FIXED_VERSION_AVAILABLE` (a fixed version from a reliable source, uncontradicted) · `PATCH_AVAILABLE` · `MITIGATION_ONLY` · `NO_KNOWN_FIX` — only when at least one advisory/intel record actually examined the CVE and offered no fix (§42); otherwise `UNKNOWN`. **A fix is never invented** (§43): no version is ever inferred from version arithmetic.
- Source disagreement on the fixed version (§86): the assessment withholds `fixedVersion`, exposes `conflictingFixedVersions` verbatim, and every surface (patch console, CVE page, copilot) says sources disagree instead of presenting one as definitive.
- Recommendations (§84 ladder): upgrade to the verified fixed version → apply vendor patch → apply mitigation → remove unused component (only on positive NOT_REACHABLE evidence) → isolate/restrict exposure (no fix + internet-facing or KEV) → monitor.
