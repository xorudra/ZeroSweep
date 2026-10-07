# Cloud Drift (Prompt 14 §63/§64)

Drift is the difference between what the estate **was** and what it
**is** — or between what IaC **declares** and what is **deployed**.

## Snapshot drift

Every inventory run records a snapshot (regions, per-type counts,
content hash). Persisting a new inventory diffs it against the
previous one and records `CloudDriftEvent` rows:

- `RESOURCE_ADDED` / `RESOURCE_REMOVED` (a removal marks the resource
  `NOT_SEEN` — an observation, §20),
- `EXPOSURE_CHANGED`, `ENCRYPTION_CHANGED`, `LOGGING_CHANGED`,
- `IAM_CHANGED` (identity set or privilege facts changed).

## IaC ↔ live drift (§62/§96)

Checkov observations (Phase 13 adapter, reused) correlate with live
inventory findings only under a **conservative rule**: the Checkov
check must map to a live cloud rule through the governed mapping
(`CKV_AWS_53 → storage-public-access`, …) **and** the resource identity
must match reliably (Terraform address's resource name equals the
deployed resource name). Unmapped rules never merge. IaC drift rows
carry a state: `MATCHED`, `DRIFTED`, `UNMAPPED` or `UNKNOWN`.

## Discipline (§64)

A drift event is an **observation, never an automatic malicious
verdict**. Drift is surfaced via `GET /cloud/drift`, the exposure page
and the `cloud.drift_detected` scan event, and feeds the compliance
stage's report — nothing is auto-remediated, ever (§7).
