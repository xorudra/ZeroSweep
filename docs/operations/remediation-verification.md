# Remediation Verification Operations (Prompt 31 §52–§67)

## Reading outcomes

- PASSED → case VERIFIED_FIXED; the finding walks to RESOLVED. The
  case can now be closed (closure engine re-checks everything).
- FAILED → the vulnerability is still there. The case is back in
  IN_PROGRESS; engineering fixes again and files a NEW claim.
- INCONCLUSIVE → evidence was insufficient. Nothing closed; gather
  better evidence or choose a stronger method. Do not re-run the same
  weak check hoping for a different answer.
- ERROR → the check itself failed (or a scan gate denied it). An
  error is information about the pipeline, never about the fix.

## Multi-observation policies

Some policies require N consecutive clean observations (e.g. for
flaky detections). PENDING_CONFIRMATION means "clean so far" — the
counter resets to zero on any FAILED observation.

## Manual verification

Reserved for cases automation cannot judge. Requires the manual
permission, a reason and evidence; high-risk findings enforce SoD
and possibly dual approval. Manual verification is fully audited —
treat it with the same seriousness as a scanner result.
