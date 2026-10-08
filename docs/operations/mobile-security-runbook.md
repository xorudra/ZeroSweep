# Mobile Security Runbook (Prompt 35)

## Daily operation
- Register applications (`POST /mobile/apps`), upload builds
  (`POST /mobile/apps/:id/artifacts` — SHA-256 is the identity;
  duplicate hashes return the same build).
- Create an analysis plan + start static analysis
  (`POST /mobile/artifacts/:id/analyze`, profile `MOBILE_STANDARD`
  by default). Plans record the dynamic gate verdict — a BLOCKED
  gate lists its reasons; fix the reason (authorization, device,
  modules), never the record.
- Review coverage (`GET /mobile/artifacts/:id/coverage`) before
  trusting a "clean" build: COMPLETED_WITH_GAPS names the unexamined
  dimensions.

## Version workflow
- On a new build, compare (`POST /mobile/apps/:id/compare`).
  FIXED_CANDIDATE rows are hypotheses — route them to Prompt 31
  targeted verification; never close from the comparison.
- REGRESSED rows link back to the Prompt 31 regression flow.

## Incidents
- A BLOCKED dynamic session is a policy success, not an outage:
  read `blockedReasons` + the `MOBILE_DYNAMIC_ACTION_BLOCKED` audit
  entry.
- Tool health: Frida reports DISABLED and Objection
  APPROVAL_REQUIRED by design (Prompt 17); IDA/Binary Ninja report
  NOT_CONFIGURED without a licensed install (§64) — both are
  honest states, not failures.
