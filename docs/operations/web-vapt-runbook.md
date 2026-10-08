# Web VAPT Runbook (Prompt 32)

## Standard flow

1. Confirm the parent target is **VERIFIED** and an assessment is
   **APPROVED** (Targets / Assessments). Without both, target creation
   is refused — that is the control working, not a bug (§6).
2. Create the Web VAPT target (`/vapt/web`) with the environment set
   correctly — PRODUCTION gets the conservative default budget (§124).
3. Run **preflight** from the target page. Work through failing checks
   in order: verification → authorization → expiry → probes.
4. Generate a **plan** and read the preview: stages, tools, blocked
   modules, budget (note any clamping), scope snapshot hash (§11).
5. For HIGH modules: attach the approval reference and confirm the
   `HIGH_RISK_TEST_APPROVED` audit event exists (§16/§168).
6. Start the scan. Watch status on the scan detail page; cancellations
   preserve partial results (§128).
7. Read results **with the coverage record**: skipped tests and
   limitations are part of the result (§147–§150).

## Profiles

Baseline is `WEB_SAFE`. `WEB_PASSIVE` for fragile targets.
`TARGETED_VERIFICATION` for retests after remediation (it feeds the
Prompt 31 verification loop, §111/§112).

## Environments

Production: conservative budgets, one-directional clamping — a
workspace can never raise a plan above the platform ceiling (§127).
Staging: broader budgets, still bounded (§125).
