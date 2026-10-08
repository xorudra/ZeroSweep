# CVSS Intelligence (Prompt 30 §12–§15)

- Every CVSS value is a `CvssAssessment` keyed by (cveId, version, source): NVD, CNA, vendor, GHSA, scanner and curated values coexist — importing a new source never rewrites another source's history (§14).
- The **preferred** assessment is selected deterministically (`selectPreferredCvss`): source priority (CISA/FIRST 95, NVD 90, CNA/vendor 85, GHSA 80, OSV 75, curated 60, scanner 40, fixture 10), then higher CVSS version, then higher score, then source name. The selection is reproducible from stored data alone.
- Version differences are meaningful: a 4.0 assessment does not replace a 3.1 one; both are shown on the CVE detail page with the preferred one badged (§13).
- A spread > 0.1 between two trusted sources (priority ≥ 60) opens a `CVSS_MISMATCH` intelligence conflict; both values stay visible until a reviewer resolves the conflict (§69–§71).
- Temporal/environmental scores are stored when a source provides them; they are never derived locally.
