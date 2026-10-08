# Remediation Ticketing (Prompt 31 §38–§49)

The canonical object is the `RemediationWorkItem`, created **before**
any external ticket. Providers (Jira, GitHub Issues, GitLab,
ServiceNow) sit behind one interface: create / update / fetch /
addComment / close / healthCheck. None is mandatory.

Payloads contain safe fields only (severity, priority, asset
reference, CVE/CWE, risk summary, safe remediation summary, due date,
DSRclone reference) and pass through classification, redaction and
secret-pattern scrubbing first — restricted evidence is never copied
into a ticket, and binary content is never attached.

Creation is idempotent on the stable key `remediation:{caseId}:{provider}`:
a retry returns the existing work item and can never mint a second
external ticket. Provider failure leaves the work item FAILED with a
failure count and a backoff `nextRetryAt` — the item is never lost.

Sync maps provider statuses into canonical states. **An external
ticket closing records a fix claim (source TICKET_SYNC) and moves the
case to FIX_CLAIMED — never to VERIFIED_FIXED.** Work items unsynced
for 7 days are flagged STALE. In this deployment the transports are
the Prompt 24 connectors, unwired until an administrator registers an
instance with a secret REFERENCE — work items therefore record
NOT_CONFIGURED honestly.
