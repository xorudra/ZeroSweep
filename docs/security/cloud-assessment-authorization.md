# Cloud Assessment Authorization (Prompt 34 §6/§8)

A cloud assessment runs only when ALL of the following hold
(`evaluateCloudAuthorization`, reused from the platform governance
core):

1. The account belongs to the caller's workspace (tenant isolation —
   foreign accounts are 404, §162).
2. An authorization record exists (linked APPROVED assessment for
   the account's target, or an explicit authorization reference)
   and is APPROVED/ACTIVE — not expired, not revoked.
3. A valid credential REFERENCE exists (never a secret value).
4. The requested regions are inside the authorized scope (Prompt 14
   `CloudScope`).
5. The caller holds RUN_CLOUD_ASSESSMENT (§139).

Failure produces a persisted BLOCKED run with the full reason list —
never a silent skip and never a partial run. Connection tests are
allowed without assessment authorization (they change nothing), but
they are permission-gated and audited.

Authorization is checked again at execution time by the worker (the
Prompt 4 orchestration re-verification), so an authorization revoked
between queueing and execution stops the run.
