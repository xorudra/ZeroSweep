# Nessus Integration (Prompt 33 §58/§59)

The Nessus Professional integration is the Prompt 11 connector — V2
uses it unchanged:

- **Lifecycle**: scan creation → policy selection (logical profiles
  NETWORK_BASELINE / NETWORK_STANDARD / NETWORK_COMPREHENSIVE) → launch
  → status → result import → export reference. `.nessus` exports are
  parsed by the Prompt 11 Nessus parser under the same hostile-input
  discipline as every import.
- **Credentials (§59)**: the Nessus API key is a secret reference,
  resolved at connector call time, sent only to the configured Nessus
  instance, and never logged. Scanner output passes through V2 secret
  redaction before normalization, so a key value appearing in plugin
  output cannot reach findings, evidence or reports (§143 test).
- **Credentialed scans**: host credentials for authenticated checks
  follow network-credential-security.md — reference-only, scoped to
  this scanner alone, single validation attempt, failures recorded as
  coverage gaps.
- **Health**: unconfigured instances report NOT_CONFIGURED honestly;
  a failed Nessus leg makes the outcome PARTIAL/ERROR, never clean.
