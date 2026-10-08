# Source-Control Integrations (Prompt 24 §10–§31)

GitHub (App preferred, §11; PAT only when explicitly configured,
§12), GitLab (OAuth/group/project tokens, §24) and Bitbucket (§27)
share one `SourceControlProvider` abstraction and one
`PullRequestSecurityAssessment` model — MRs and PRs are the same
record (§26).

Repository identity is `(provider, externalRepositoryId,
installationId)` — never the mutable name alone (§29).
`RepositoryIntegrationLink` binds that identity to a platform
`SourceRepository`; the link table IS the repository allowlist (§86):
a webhook for an unlinked repository is recorded and ignored.

Synchronization imports metadata (default branch, visibility,
languages, archived) into staging `SourceRepository` rows with
bounded pagination and per-integration checkpoints (§98/§99). Sync
never creates a target, never verifies one, and never approves an
assessment. Code ingestion itself stays on the Prompt 12 governed
snapshot path; submodule URLs pass the ingestion policy in
`docs/security/repository-ingestion-security.md`.
