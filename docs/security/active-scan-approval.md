# Active scanning approval model (Prompt 8 §8/§12/§37–§45)

Active web scanning (`ACTIVE_WEB_SCANNING`) is **INTRUSIVE** and
**disabled by default**. It is not part of `WEB_BASELINE` or any other
default profile, and the `ACTIVE_SECURITY_ANALYSIS` stage exists in the
stage library only — no profile template includes it. Enabling active
analysis for an assessment is a chain of independent gates; every gate
must pass at execution time, not just at approval time:

1. **Verified target** — the target's ownership verification is current.
2. **Approved scope** — a scope snapshot exists and the assessment is
   `APPROVED`.
3. **Platform policy** — active testing is enabled for the deployment.
4. **Authorization role** — the requesting user holds an authorized role.
5. **Budget headroom** — the scan budget's `maxActiveScanRequests`
   (admin hard caps apply) is not exhausted.
6. **A specific approval** — a `ScanApproval` record (Owner/Admin
   granted) for this assessment + capability, unexpired, unrevoked, and
   whose **scope snapshot hash matches the current scope**. Any scope
   change invalidates the approval automatically (§43); expiry is
   enforced (§42).

Approvals are auditable: `ACTIVE_SCAN_APPROVAL_GRANTED`,
`ACTIVE_SCAN_APPROVAL_REVOKED`, and denials emit `ACTIVE_SCAN_DENIED`
(§72). The pre-scan review surface shows target, scope, exclusions,
chosen scanner, risk level, authentication profile, budget, rate limits
and expected duration with an explicit confirmation before any active
run starts (§40).

**Phase status:** the gate chain, approval storage, expiry/revocation,
scope-hash binding and budget model are implemented and unit-tested, and
the connectors expose `startActiveScan` behind them — but active scans
are **prepared, not enabled**: a fully-approved request returns
`started: false` in this phase. Intrusive execution arrives only in a
later phase with its own review.
