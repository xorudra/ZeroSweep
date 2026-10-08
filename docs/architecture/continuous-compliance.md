# Continuous Compliance (Prompt 26 §28/§94/§95/§104/§105)

`ContinuousControlMonitoringService` (MonitoringService) re-evaluates
technical controls when the underlying security state changes.
State changes arrive as signal observations or as derivation from
platform tables (identity policy, posture snapshots, findings,
posture assessments). A change event names the affected signal keys;
**only controls whose test definitions include those keys are
re-evaluated** (§139) — there is no full-assessment rerun.

## Drift events

Transitions produce `ComplianceDriftEvent` rows (§95):
CONTROL_FAILED, CONTROL_RECOVERED, EVIDENCE_STALE, EVIDENCE_EXPIRED,
NEW_GAP, RISK_INCREASED. Critical transitions are also routed as
in-app notifications through the platform notification discipline
(external providers remain honestly NOT_CONFIGURED, as in Prompt 22).

## Schedules

`ControlTestSchedule` (§104) registers a cron for re-evaluation of a
single control. Schedules are **safe/read-only** (§105): the schedule
row stores no command, cannot start a scan, and its execution path is
the same derivation+evaluation used interactively. If fresh technical
evidence requires a scan, that goes through the governed scheduler /
scan pipeline with its own authorization (§27).
