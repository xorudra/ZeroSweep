# Administrator Guide (Prompt 40 §156)

Audience: organization administrators and platform operators.

## Organization administration
- Members, roles (ADVANCED_RBAC entitlement), invitations (§76–§79),
  SSO/SCIM (Prompt 23; SSO is entitlement-gated, §80).
- Lifecycle: suspension, cancellation → retention → deletion with
  impact preview, approval and legal hold (§86–§94). Deletion is an
  operator process; requesting it never immediately destroys data.
- Billing roles: VIEW_BILLING / MANAGE_BILLING / VIEW_USAGE /
  MANAGE_PLAN / MANAGE_LICENSE (§135).

## Platform administration (deployment level)
- `/admin/product` + `/api/v1/platform/*`: organizations,
  subscriptions, licenses, usage, trials, features, plans, quota
  overrides (platform-issued only, §138), release state.
- Platform admin is a **separate** flag from tenant roles (§96–§98),
  bootstrapped from `PRODUCT_PLATFORM_ADMIN_EMAILS` at registration.
- Support access: reason-bound, scope-bound, tenant-approved,
  expiring, audited sessions (§100–§103). No silent impersonation.
  Platform admins can never view user passwords or raw tenant
  integration secrets (§104/§105); organization views are metadata
  only (§106).
- Operations: backups/restore, kill switches and SLOs live in the
  Prompt 38 platform-ops surface (`/admin/platform`).
