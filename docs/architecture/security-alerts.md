# Security Alerts (Prompt 28 §30–§40)

## Lifecycle

`SecurityAlert` statuses: `NEW, TRIAGED, INVESTIGATING, CONTAINED,
RESOLVED, CLOSED, DUPLICATE`. Every alert — detection, correlation,
indicator match or manual — is created through the single
`AlertService.raiseAlert` path, which applies, in order:

1. **Suppression check (§39/§40).** An active suppression applies
   only when *every* non-null scope field (rule, asset, identity,
   source) matches. Suppressions require at least one scope field
   and an expiry (≤ 90 days) — permanent or unscoped suppression
   cannot be created.
2. **Fingerprint dedupe (§32).** The fingerprint hashes rule +
   version + group key + asset + identity + indicator. An open
   alert with the same fingerprint absorbs the occurrence
   (`occurrenceCount + 1`, `lastSeen` updated) instead of a new row.
3. **Priority (§33).** A deterministic weighted score (severity,
   confidence, asset criticality, internet exposure, KEV presence,
   identity privilege, occurrence count, business hours) maps to
   P1–P4, with the contributing factors stored on the alert for
   analyst review. SOC SLAs default per priority and are
   workspace-overridable (`SocSlaConfig`); the evaluation tick
   flags at-risk and breached alerts and emits `SOC_SLA_AT_RISK` /
   `SOC_SLA_BREACHED` into the P27 lake exactly once per alert.

## Triage (§36–§38)

Triage decisions (`TRUE_POSITIVE`, `FALSE_POSITIVE`,
`BENIGN_POSITIVE`, `DUPLICATE`, `NEEDS_INVESTIGATION`, `ESCALATED`)
are immutable `AlertTriage` rows. First triage stamps
acknowledgement (the MTTA anchor). False-positive decisions feed
per-rule FP rates and detection health — and nothing else: a rule
is never auto-disabled by its FP rate.
