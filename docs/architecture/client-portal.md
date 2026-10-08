# Client Portal (Prompt 37 §95–§109)

The portal lets an external client see **their** published findings
and finalized reports — nothing else.

Model:

- `ClientOrganization` — a client of the workspace.
- `ClientEngagement` — an engagement under a client; reports and
  publications hang off it.
- `ClientPortalUser` — binds one user account to exactly one client
  organization with one portal role (CLIENT_VIEWER /
  CLIENT_REMEDIATOR / CLIENT_MANAGER, §128).
- `ClientFindingPublication` — the ONLY path by which a finding
  becomes portal-visible (§100). Unpublishing revokes immediately.

Request flow: every portal handler resolves the caller's binding
first; engagements, findings and reports are then reachable only
through that binding. Finding payloads are built exclusively by the
SDK allowlist projection (`projectFindingForClient`): client-visible
evidence (CLIENT/REPORT classes) and CLIENT comments only, all text
redacted, status in the §7 vocabulary.

Client actions: comment (forced CLIENT visibility), claim fix
(lands on the Prompt 31 case state FIX_CLAIMED — never verified
closure), request retest (a QUEUED governed retest request), download
finalized reports, read notifications (§108 — notification bodies are
built only from client-visible fields).

See `security/client-portal-isolation.md` for the boundary rules.
