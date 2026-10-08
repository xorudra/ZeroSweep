# Jira Integration (Prompt 24 §46–§54)

- **Mappings**: `JiraProjectMapping` (finding type / team / asset
  group → project + issue type) with one workspace default (§47).
- **Creation**: one ticket per (finding, integration); duplicate
  creation returns the existing ticket (§49/§124). The summary uses
  the finding title; the body uses the governed template (§50) with
  sanitized, secret-scrubbed content.
- **Sync**: bidirectional three-way sync. External status changes
  update the ticket; a closed ticket never resolves the finding
  (§52). Two-sided changes create conflicts for analyst resolution
  (§53/§126). Sync cadence and manual sync share one service (§58).
- **Credentials**: API token as a secret reference; the connector
  requests only issue create/read/update on the mapped projects.
