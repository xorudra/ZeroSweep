# Container Registry Security (Prompt 34 §47)

- Registries register with a credential REFERENCE only; pull
  credentials are resolved by the worker from Secrets Management at
  scan time and never stored on the registry record, in logs or in
  image metadata.
- Private registries are accessed read-only: the platform pulls
  image metadata/manifests and layers for analysis; it never pushes,
  tags, deletes or mutates registry content.
- Image identity is the digest (§49): scans, SBOMs and findings bind
  to digests so a re-tagged image cannot inherit a clean result.
- Registry reachability problems produce coverage gaps
  (TOOL_UNAVAILABLE / SECRET_UNAVAILABLE), never fabricated results.
- Unapproved registries are flagged by image policy (§62) when they
  appear in workload/image inventory.
