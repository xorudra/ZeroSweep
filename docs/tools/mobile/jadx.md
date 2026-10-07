# JADX (Prompt 17 §19)

Android decompiler run in the static sandbox on
`MOBILE_STATIC_ANALYSIS` workers (no network). Decompiled output is
an **analysis artifact**: it is never executed, and access is
RBAC-gated (`VIEW_MOBILE_SOURCE_ARTIFACTS`, audited). Parsed output
feeds endpoint extraction, API-call inventory and metadata-only
secret detection.
