# SOC 2 (AICPA Trust Services Criteria) in DSRclone (Prompt 26)

Shipped catalog version: SOC_2 2017 (CC1–CC9 + Availability A,
Processing Integrity PI, Confidentiality C, Privacy P series).
Criteria IDs/titles are the published reference structure; the full
criteria text is licensed AICPA material and is imported by the
organization, not bundled.

Mapping notes:

- CC6.1 (logical access) is supported by the MFA, encryption and
  access-control controls (PARTIAL — access provisioning process
  evidence is manual).
- CC7.2 (monitoring) maps to continuous control monitoring and
  logging signals; CC7.3/CC7.4 to the incident-response process
  control (manual evidence).
- CC8.1 (change management) maps to the DevSecOps gates +
  change-process controls (PARTIAL).
- A1.2 (backup/recovery) maps to the backup-verification control.
- P-series privacy criteria are manual-evidence by default.

A SOC 2 report is issued by a licensed CPA firm after an observation
period. DSRclone prepares and organizes evidence; **it does not and
cannot issue SOC 2 reports or opinions.**
