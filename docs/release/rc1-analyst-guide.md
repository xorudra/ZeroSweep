# RC1 Analyst Guide (Prompt 39 §309)

## The governed flow (nothing skips steps)

Register target → verify ownership → define scope → create assessment
→ obtain approval → run scan → review canonical findings → remediate →
verify by retest → report. The E2E suite drives exactly this flow;
the UI enforces the same order the API does.

## Running assessments

- Pick a profile (recon, web, API, network, cloud, container, mobile,
  binary, source…). Profiles expand to governed DAG stages; tools run
  SAFE templates/checks only. Intrusive, brute-force, exploit and
  DoS capabilities are policy-excluded structurally — not hidden
  behind a flag you can flip in the UI.
- Masscan-class tools require the explicit gated workflow (P33);
  wireless is passive-only; AD collection is read-only.
- Watch progress live; cancel any time (process tree is terminated).
  Coverage gaps are reported as gaps — a scan that skipped a stage
  says so (`COMPLETED_WITH_GAPS`), it does not claim full coverage.

## Findings

- Everything lands as canonical findings with a fingerprint,
  provenance (which tools, which runs) and a deterministic Risk V3
  score with visible factors. The same issue from multiple scanners
  converges; a different-domain observation of the same CVE does not
  false-merge.
- Lifecycle: triage → confirm → fix-claim → **verify by retest** →
  close. "Fixed" from a ticket alone is FIX_CLAIMED, never
  VERIFIED_FIXED. Risk acceptance is a governed exception with
  expiry and separation of duties.
- Platform candidates (V2 authorization-matrix mismatches, EASM
  candidates, posture signals) are **not** findings until confirmed —
  treat them as leads.

## AI copilot

- Ask questions, request summaries, draft remediation guidance. The
  copilot only sees your workspace, cites the records it used, and
  refuses when evidence is insufficient. It cannot run scans, change
  scope, approve anything, or execute commands — by construction,
  not by prompt. Treat its drafts as analyst assistance; approvals
  and risk decisions remain yours.

## Reports

- Generate immutable snapshots (PDF/HTML/JSON/CSV) — a finalized
  report never changes afterwards; revisions create new versions.
  Client-visible content is a published projection: internal notes
  and restricted evidence never cross into the portal.
