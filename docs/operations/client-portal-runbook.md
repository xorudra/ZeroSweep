# Runbook: Client Portal (Prompt 37 §95–§109)

Setup:

1. Create the ClientOrganization (admin API), then the engagement.
2. Create the client's user account through the normal identity
   flow, then bind it with `POST /client-portal/admin/portal-users`
   (one binding per user, one portal role).
3. Publish findings deliberately — publication is per finding per
   engagement. Review the client projection before publishing:
   only CLIENT/REPORT evidence and CLIENT comments travel.
4. Scope finalized reports to the client (clientOrganizationId or
   engagementId) for portal download.

Operations:

- Unpublish immediately when a finding was published in error;
  revocation is instant and audited.
- Client fix claims appear as FIX_CLAIMED cases on the remediation
  board — route them into verification like any other claim.
- Watch CLIENT_PORTAL_ACCESSED audit events for unusual access
  patterns; portal 404s are indistinguishable by design, so audit is
  the enumeration-detection surface.
- Never paste internal notes into a CLIENT comment "for context" —
  write a separate client-appropriate summary instead (§34).
