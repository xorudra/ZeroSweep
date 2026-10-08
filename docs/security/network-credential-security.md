# Network Credential Security (Prompt 33 §59–§63)

- Scanner API credentials (Nessus/OpenVAS) and credentialed-scan
  credentials are **secret references only** end to end. No table in
  the V2 schema has a plaintext secret column; no API response, log,
  finding, evidence blob or report carries a secret value.
- Normalization REDACTS secret values from scanner output before
  storage: known run secrets are replaced verbatim, and generic
  secret-shaped patterns (api_key=, Bearer tokens, private keys) are
  redacted as a second line of defence. The §143 test plants a
  synthetic secret in a scanner fixture and proves its absence from
  every normalized field.
- Credentialed scanning is scoped: a credential is explicitly provided
  for ONE scanner (the injection plan names exactly one recipient and
  excludes every other tool), is temporary where possible, and
  requires RUN_CREDENTIALLED_NETWORK_SCAN.
- Credential validation is lockout-safe: a single bounded attempt. An
  authentication failure is recorded as a coverage limitation — never
  retried aggressively, never escalated into brute force (§145).
- SNMP secrets, passwords and private keys are never written to
  findings, logs or reports (§62).
