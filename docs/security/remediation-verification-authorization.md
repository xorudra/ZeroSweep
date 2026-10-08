# Remediation Verification Authorization (Prompt 31 §55–§58)

Verification is powerful — it is the only path to VERIFIED_FIXED — so
it is authorized at three layers:

1. **Permission**: requesting verification needs
   `REQUEST_VERIFICATION`; manual verification additionally needs
   `PERFORM_MANUAL_VERIFICATION`.
2. **Policy**: the method must be allowed for the finding's category
   by the VerificationPolicy, and the case must hold a fix claim
   (after a failed verification, a *new* claim).
3. **Scan gates**: rescan/retest methods open a governed Prompt 11
   RetestRequest. The target must still be VERIFIED and an assessment
   APPROVED; scope and tool policy come from that machinery. The
   orchestration layer cannot mint approvals, widen scope, or run a
   side-channel scan. Denials are recorded on the job.

Scope is the smallest sufficient: the original affected host,
endpoint or component — a fix verification never re-scans a fleet.
High-risk findings add segregation of duties and, where policy
requires, dual approval (§67/§122).
