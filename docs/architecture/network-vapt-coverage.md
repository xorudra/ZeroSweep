# Network VAPT Coverage (Prompt 33 §121–§123)

Coverage is computed from what actually ran:

- authorized hosts vs discovered hosts vs scanned hosts;
- port coverage and service-identification coverage;
- vulnerability-scanner coverage (null when no scanner was in the
  profile — "not applicable", never 0% or 100% by fiat);
- credentialed coverage where the profile is credentialed.

Every gap is a recorded limitation with a reason: host unreachable,
firewall filtering, scanner unavailable, authentication failed, budget
exhausted, policy blocked. Completion labels follow the evidence:

- `COMPLETED` — every planned dimension ran on every discovered host
  with no limitations;
- `COMPLETED_WITH_GAPS` — finished, with recorded limitations;
- `PARTIAL` — a stage failed or was skipped;
- `FAILED` — nothing was scanned and a stage failed.

A scan with incomplete coverage must not appear fully complete, and an
unrun scan reports null coverage with named limitations — never a
fabricated 100%.
