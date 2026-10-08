# Client Portal Isolation (Prompt 37 §97/§101/§144)

The portal is a hard tenant boundary, enforced in the service layer:

1. **Binding-first resolution.** A portal request resolves the
   caller's `ClientPortalUser` binding (user → one client
   organization). No workspace or client parameter is accepted from
   the request for scoping; engagements are loaded through the
   binding only.
2. **404, never 403.** Another organization's engagement, an
   unpublished finding, an unfinalized report — all answer 404,
   indistinguishable from nonexistence. Clients cannot enumerate
   other tenants or even learn that a finding exists.
3. **Publication is the only visibility path.** A finding reaches
   the portal exclusively through an active
   `ClientFindingPublication` for that engagement. There is no
   "clientVisible" flag on Finding to flip by accident.
4. **Allowlist projection.** Responses are built by
   `projectFindingForClient` from an explicit field list. Internal
   comments, INTERNAL/RESTRICTED evidence, assignment data, risk
   internals and other engagements have no code path into a portal
   payload.
5. **Audit.** Portal reads and actions write audit events
   (CLIENT_PORTAL_ACCESSED, CLIENT_COMMENT_ADDED, FIX_CLAIMED,
   VERIFICATION_REQUESTED, REPORT_DOWNLOADED).

Tests: `client-portal.spec.ts` pins isolation (§144), projection
hygiene (§101/§143) and revocation (§100).
