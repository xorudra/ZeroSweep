# Object storage

S3-compatible (MinIO locally). Business logic depends on storage **keys**, not
on MinIO directly, so the provider can change. Layout (by key prefix):
`workspaces/<id>/scans/<scanId>/raw|artifacts|evidence/` and
`workspaces/<id>/reports/<reportId>.*`. Buckets are private by default; access
is mediated by the API with tenant checks. Output limits (stdout/stderr/
artifact size & count) are defined in `@dsrclone/security-sdk`
(`DEFAULT_LIMITS`) and enforced by workers.
