# Continuous Security Engine (Prompt 22)

The continuous-security engine keeps an authorized environment under
continuous, governed observation. It is built from five cooperating
parts, all in `apps/api/src/modules/continuous-security/`:

1. **Monitoring policies** (§3–§5) bind a target selector and a
   SAFE_AUTOMATED scan profile to a frequency. Selectors resolve
   inside the workspace only; resolution is a filter, never an
   authorization.
2. **The scheduler** (see `security-scheduler.md`) materializes due
   work through the existing gated paths — OrchestrationService for
   scans, Prompt 20 report definitions, Prompt 16 validation
   requests, Prompt 11 retests. It never runs a scanner directly.
3. **Snapshots** (§29–§32): posture, asset and finding snapshots are
   immutable captures. History is read from them, never recomputed.
4. **Drift** (see `security-drift.md`): snapshot comparisons and
   intelligence movement produce asset/finding/risk drift events.
   KEV/EPSS/CVSS movement re-scores findings with Risk Engine V3
   without re-scanning (§50).
5. **Automation**: typed workflows (see `security-workflow-engine.md`)
   and the provider-neutral notification router (see
   `security-notifications.md`).

## Safety posture

- Only `SAFE_AUTOMATED` profiles can be scheduled (§9). The closed
  classification lives in `packages/security-sdk/src/continuous/safety.ts`
  and is enforced at policy creation, schedule creation and again at
  every fire time.
- The §11 never-schedule list (password spraying, credential
  stuffing, brute force, Kerberoasting, AS-REP roasting, NTLM relay,
  credential dumping, RCE exploitation, privilege escalation, lateral
  movement, persistence, deauthentication, evil-twin AP, Wi-Fi
  cracking, arbitrary Frida, arbitrary debuggers, destructive API
  operations) is classified `PROHIBITED_AUTOMATION` in code and
  covered by tests.
- Authorization is rechecked before EVERY run (§25): assessment
  APPROVED + target VERIFIED + fresh DNS scope revalidation (§26).
  Expiry produces a persisted BLOCKED run — never a silent retry,
  never a resurrected approval.

## Honest limits of this deployment

- No intelligence data source is configured, so INTEL_SYNC schedule
  runs record `INTEL_SOURCE_NOT_CONFIGURED` and the dataset stays
  NEVER_SYNCED (Prompt 11 posture). Drift/recalculation still run
  over whatever intel rows exist locally.
- External notification providers are not configured; their records
  read RECORDED_NOT_DELIVERED / NOT_CONFIGURED. In-app delivery is
  real (the /notifications inbox).
- The scheduler advances when `tick()` is invoked (operator endpoint
  `POST /monitoring/tick` or a deployment timer). No hidden daemon
  is required for correctness; tests drive the tick with a fake
  clock.
