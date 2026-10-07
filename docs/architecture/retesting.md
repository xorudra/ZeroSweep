# Retesting (Prompt 11 §55–§58)

## Flow

1. Analyst requests a retest (REQUEST_RETEST permission) on a finding in
   REMEDIATED (or CONFIRMED/IN_PROGRESS for planning). The API derives a
   targeted plan from the finding's provenance: original source tool,
   original check reference (from evidence metadata), asset/service/
   endpoint, canonical fingerprint.
2. A `RetestRequest` row (QUEUED) is persisted with the previous-evidence
   reference; a REMEDIATED finding moves to RETEST_PENDING. The job is
   enqueued (IDs only); enqueue failure never loses the request.
3. The worker's RetestRunner prepares a single-stage child scan (same
   assessment, target and scope snapshot) and executes it through the
   ordinary StageExecutor — authorization/scope/policy/budget gates are
   re-run by construction (§57).
4. Judgement: stage COMPLETED + original fingerprint absent → RESOLVED;
   present → REOPENED (lifecycle → CONFIRMED, reopenedAt set,
   recurrence +1). Stage DENIED/FAILED/unavailable → retest FAILED and
   the finding stays in RETEST_PENDING — never a silent pass.

## Evidence

Previous evidence (the original finding + plan rationale) and new
evidence (child scan id, produced fingerprints, judgement detail) are
both preserved on the retest record and the finding history (§58).
Complete retest history is listed per finding.
