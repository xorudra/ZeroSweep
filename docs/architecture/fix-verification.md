# Fix Verification (Prompt 31 §52–§67)

Verification methods are governed by policy per finding category
(SDK `VERIFICATION_POLICY`): SAFE_RESCAN, TARGETED_RETEST,
SAST_RESCAN, SCA_RESCAN, SBOM_REEVALUATION, CONFIGURATION_RECHECK,
CLOUD_POSTURE_RECHECK, MANUAL_EVIDENCE_REVIEW. A method outside the
category's policy is rejected.

Rescan/retest methods open a governed Prompt 11 `RetestRequest` — the
same VERIFIED-target + APPROVED-assessment + scope/policy gates as
any scan. A gate denial is recorded on the job (`gateDenied`); it is
never bypassed. Verification always uses the smallest sufficient
scope: the original affected asset/endpoint/component.

Every observation stores before/after evidence. Outcomes:

- **PASSED** — vulnerability absent, evidence sufficient, and the
  configured count of *consecutive* clean observations reached
  (multi-observation confirmation, §65).
- **FAILED** — still present: the case returns to actionable work and
  a NEW fix claim is required before retesting.
- **INCONCLUSIVE** — evidence insufficient: nothing closes.
- **ERROR** — the scanner errored: an error is never a pass (§63).

Manual verification needs `PERFORM_MANUAL_VERIFICATION`, a reason and
evidence. On high-risk findings (P0/P1, CRITICAL or KEV-listed) the
fix claimer may not verify their own fix (SoD, §122), and policy may
require a second approver who differs from both (§67).

SBOM reevaluation (§93) compares the component's current
vulnerability-match state: still AFFECTED means still present.
