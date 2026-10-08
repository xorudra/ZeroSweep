# Web VAPT Troubleshooting (Prompt 32)

| Symptom | Meaning | Action |
| --- | --- | --- |
| Target creation refused: "not VERIFIED" | Parent target has not passed ownership verification (§6) | Complete target verification first |
| Target creation refused: "No APPROVED assessment" | No active authorization (§173) | Get the assessment approved; expired approvals must be renewed (§174) |
| Preflight BLOCKED, `PROBE_TRANSPORT` UNKNOWN | No live probe transport is wired in this deployment | Expected in the local/Docker-less stack — reachability is reported honestly; do not "fix" by assuming READY |
| Preflight BLOCKED, `REDIRECT_SCOPE` FAIL | The target redirects outside the frozen scope (§9) | Review the recorded redirect; widen scope only via a new authorized snapshot |
| Plan shows blocked HIGH module | The §16 gate failed: permission, approval reference, or active authorization missing | Check the reason string on the blocked module; approvals are audited |
| Budget notice "clamped" | Requested budget exceeded the platform ceiling (§127) | Expected — ceilings are one-directional |
| Scan `COMPLETED_WITH_GAPS` | Budget exhausted, a tool was unavailable, or stages were skipped | Read the coverage record's skipped list + limitations (§147) |
| Scan `FAILED` with parser warnings | Tool output could not be parsed (§188) | Check tool health → parser compatibility; a parser failure is never a clean result |
| Matrix rows rejected | Non-fixture resource identifier (§98) | Use template/fixture identifiers; broad enumeration is forbidden by design |
| Scenario rejected | A step describes a destructive action (§102) | Rewrite as a safe observation step |
| Findings missing after a "successful" run | Check coverage first — untested surface produces no findings, and that is stated in limitations | Never report the target as clean; report the coverage |

## Backup/restore (§199 posture)

V2 records are ordinary Postgres rows under the workspace; they ride
the platform backup/restore flow. Scope snapshots and specification
snapshots are immutable rows — a restore must reproduce them
bit-for-bit (hashes verify this).
