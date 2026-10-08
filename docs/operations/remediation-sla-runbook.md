# Runbook: Remediation & SLA (Prompt 37 §23–§32)

- Watch the SLA dashboard (`/vulnerabilities/sla`): OVERDUE first,
  then AT_RISK (≥75% of window), then the verification backlog.
- A fix claim is not a fix. Cases sit in FIX_CLAIMED until the
  governed verification (Prompt 31 retest) passes; only then does a
  case become VERIFIED_FIXED and a finding FIXED_VERIFIED.
- Regressions (the same issue returns) reopen the case and increment
  regression counters — report them separately from new findings
  (§117 metrics keep regression rate visible).
- SLA exceptions (§19 SLA_EXCEPTION) exempt a finding from OVERDUE
  while active; they expire like every exception. Expired exceptions
  stop applying at the sweep — re-approve explicitly if still needed.
- MTTR reviews must quote the three clocks separately: time to
  triage, time to fix claim, time to verified closure.
