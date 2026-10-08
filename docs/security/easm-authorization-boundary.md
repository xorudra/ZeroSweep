# EASM Authorization Boundary

The boundary is structural, enforced in services and pinned by tests
(`apps/api/src/modules/easm/easm.spec.ts` §133–§136, §70/§135).

1. **Discovery ≠ authorization.** A discovery run can only create
   candidates (`activeTestingStatus = NOT_AUTHORIZED`), observations,
   snapshots, and drift. It cannot create targets, verify targets,
   approve assessments, or start scans — those code paths do not
   exist in the EASM module.
2. **Ownership ≠ active testing.** Verifying a root
   (`VERIFY_ASSET_OWNERSHIP`: OWNER/ADMIN/SECURITY_ENGINEER) sets
   `authorizationStatus = VERIFIED` and leaves
   `activeTestingStatus = NOT_AUTHORIZED`.
3. **Active authorization is separate and segregated (§118).**
   `AUTHORIZE_EASM_ACTIVE_TESTING` is OWNER/ADMIN only. Even then it
   authorizes *governed discovery probes* (approved ports, bounded
   HTTP) — scanning still requires the platform's VERIFIED target +
   APPROVED assessment path.
4. **Third-party and shared assets** can never be active-tested;
   declaring a candidate third-party is terminal for promotion and
   active authorization.
5. **The AI copilot cannot authorize** (§149): authorization-shaped
   questions are refused deterministically (`AI_CANNOT_AUTHORIZE`)
   and `executed` is always `false`.
6. **RBAC (§117)** is enforced per-route by `requireEasmPermission`;
   every grant, verification, promotion, and evidence access is
   written to the audit log (§119 actions `EASM_*`).
