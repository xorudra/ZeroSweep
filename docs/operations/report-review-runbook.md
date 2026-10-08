# Runbook: Report Review & Finalization (Prompt 37 §62–§94)

1. Generate the report (Prompt 20 flow) — this freezes the snapshot.
   After generation, finding edits do not change the report.
2. Check the redaction preview
   (`GET /security-reports/:id/redaction-preview`). Any warning must
   be resolved at the source (the finding/evidence text) and the
   report regenerated; finalization refuses a dirty snapshot.
3. Submit for review; reviewers either approve or request changes
   with notes (CHANGES_REQUESTED returns the report to the author).
4. Approve (separate approver when the report's policy requires it).
5. Finalize: the snapshot is frozen into an immutable ReportVersion
   and the rendered artifact is SHA-256 hashed. Record the
   artifactHash in the engagement's document control log.
6. Share deliberately: client scoping for portal delivery, or a
   share link with the shortest practical expiry and a download
   limit. Revoke links when the engagement closes.
7. AI drafts may accelerate the executive summary, but every claim
   is fact-checked against the snapshot before storage, and a human
   approves the report — AI cannot finalize (§89).
