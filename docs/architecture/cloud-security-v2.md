# Cloud Security V2 (Prompt 34)

V2 deepens the Prompt 14 multi-cloud engine without replacing it.
The Prompt 14 SDK (`cloudsec/`) still owns provider adapters
(Prowler, ScoutSuite, CloudMapper, Steampipe, ROADtools), the
read-only inventory connectors and the posture analysis
(`analyzeCloudInventory`). The Prompt 34 SDK module (`cloudv2/`)
adds connection tests, immutable resource snapshots + drift, IAM
posture signals + attack-path candidates, baselines, coverage, the
three orchestrators and the AI/NL surface.

API: `apps/api/src/modules/cloud-security-v2`,
`container-security`, `kubernetes-security`. V2 routes never collide
with the Prompt 13/14 surfaces; container scans/SBOMs delegate to the
governed Prompt 13 paths on the same models.

Non-negotiables (unchanged from V1): cloud access is READ-ONLY at the
type level; credentials are secret references only; offensive
families stay DISABLED descriptors; assessment requires an APPROVED
authorization (Prompt 34 §8) and otherwise produces a BLOCKED run
with recorded reasons; findings enter the canonical Finding store
only through the governed scan path, so Risk Engine, dedup,
correlation, SLA, reporting, AI and dashboards keep one truth.

Honest state: live provider transports are deliberately unwired in
this deployment — connection tests report UNREACHABLE /
NOT_CONFIGURED and assessments run over recorded inventory with the
gap surfaced in coverage (COMPLETED_WITH_GAPS), never "clean".
