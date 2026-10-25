# Cloud Credential Model (Prompt 14 §6/§9/§11)

Cloud credentials exist in ZeroSweep **only as secret references** —
the same model as Phase 8 scanner instances and Phase 13 cluster
connections, extended to cloud accounts.

## The rules

1. A `CloudAccount` row stores `credentialReference`: a secret-manager
   reference NAME (e.g. `vault:prod/aws/assessment-role`). An AWS
   secret access key, Azure client secret, GCP service-account private
   key, access token or refresh token **never** appears in the
   database, an API payload, a scan plan, a log line or a report.
2. Registration and validation **refuse secret-shaped values**: the
   API validates the reference with the SDK's reference/shape checks
   (`isValidCredentialReference`, `looksLikeSecretValue`) and rejects
   anything that looks like a credential value.
3. Adapter configuration carries the reference name only. The value is
   resolved **inside the CLOUD_ANALYSIS worker boundary** at execution
   time — the one place a credential may exist, transiently.
4. **Credential leases (§11):** at `CLOUD_AUTH`, the worker issues a
   job-scoped lease recording the account, the reference NAME and its
   lifecycle — never the value. TTL is capped at **3600 seconds**;
   leases expire with the job.
5. Inventory payloads are treated as hostile: if a provider response
   or fixture ever carries secret-shaped material (e.g. in a tag), it
   is **redacted/fingerprinted before persistence** (§100) — the test
   suite proves the value appears nowhere in stored state.

## Validation honesty (§9)

`POST /cloud/accounts/:id/validate` checks what the API can truthfully
check — that a well-formed reference exists. A missing reference sets
the account `NOT_CONFIGURED`; a secret-shaped stored reference sets
`VALIDATION_FAILED`. The provider identity itself is re-validated by
the worker at scan time under the lease, before any inventory is
collected. Accounts that cannot be validated fail their scans
honestly; nothing falls back to simulation.
