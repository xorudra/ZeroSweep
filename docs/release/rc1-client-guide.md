# RC1 Client Guide (Prompt 39 §310)

Welcome — this guide explains what you see in the ZeroSweep client
portal during your security assessment.

## What you see (and don't)

- You see **your** organization's engagements, published findings,
  remediation tasks assigned to you, and shared reports.
- You do **not** see the provider's internal notes, raw scanner
  output, other clients' data, or unpublished drafts. Portal content
  is a published projection — if something is missing, it has not
  been published yet; ask your engagement manager.
- Roles: CLIENT_MANAGER (oversees the engagement), CLIENT_REMEDIATOR
  (works assigned fixes), CLIENT_VIEWER (read-only).

## Findings and remediation

- Each published finding shows severity, status, due date (SLA) and
  guidance. When you believe an issue is fixed, mark it
  **fix claimed** — the provider then verifies by retest. Only a
  passed retest moves it to **verified fixed**; this protects you
  from false closure.
- You can attach evidence and comments to your remediation tasks.
  Do not paste real passwords or private keys anywhere in the
  portal — reference your own secret store instead.

## Reports and share links

- Reports are immutable snapshots: the report you received never
  silently changes; updates arrive as new versions.
- Share links expire and can be revoked by the provider. A link that
  returns "not found" has expired or been revoked — request a fresh
  one rather than retrying.

## Security of your access

- Use a strong, unique password and enable MFA when offered.
- Portal sessions and API access are tenant-isolated: your data is
  never visible to another client, including through search or
  exports.
