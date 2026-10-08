# Bitbucket Integration (Prompt 24 §27)

Workspace/repository access via app password or OAuth, secret
reference only. Repository webhooks verify HMAC signatures and feed
the same PR assessment + gate flow as GitHub/GitLab. Repository
sync imports metadata (workspace, slug, default branch) into staging
rows + links; unlinked repositories' webhooks are recorded and
ignored.
