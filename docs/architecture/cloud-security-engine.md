# Cloud Security Engine (Prompt 14)

Multi-cloud security assessment for **AWS, Azure and GCP**. Cloud
accounts are registered as verified targets (§4) and assessed
**read-only, forever** (§7): no code path in this platform creates,
modifies or deletes a cloud resource, no remediation action exists,
and privilege escalation is never attempted. The engine turns provider
configuration metadata into normalized inventory, findings, compliance
evidence, drift and risk paths — data analysis only.

## Pipeline (§86)

```
AUTHORIZATION_CHECK → SCOPE_VALIDATION → CLOUD_AUTH → CLOUD_INVENTORY
→ IAM_ANALYSIS → NETWORK_ANALYSIS → STORAGE_ANALYSIS
→ ENCRYPTION_ANALYSIS → LOGGING_ANALYSIS → CLOUD_CSPM → NORMALIZATION
→ CORRELATION → RISK_ANALYSIS → CLOUD_COMPLIANCE → QUALITY_GATE
→ REPORT_GENERATION
```

Profiles (§12): `CLOUD_INVENTORY` (minimal), `CLOUD_BASELINE`,
`CLOUD_COMPREHENSIVE`, `IAM_REVIEW`, `PUBLIC_EXPOSURE_REVIEW`,
`COMPLIANCE_ASSESSMENT`, `IAC_TO_CLOUD_CORRELATION`. The legacy `CLOUD`
profile name resolves to the `CLOUD_BASELINE` chain.

- **CLOUD_AUTH** validates the registered account and issues a
  job-scoped credential lease (§11). An account without a credential
  reference reports **NOT_CONFIGURED** and the scan fails honestly —
  inventory is never fabricated.
- **CLOUD_INVENTORY** runs the provider connector matching the
  account's own provider (the plan selects all three; execution
  narrows). Connectors collect security-relevant **metadata only**
  (§13): no object contents, no secret values, no key material, no
  database rows.
- **Analysis sections** are platform stages over the persisted
  inventory — IAM, network, storage/database, encryption/KMS,
  logging/security services. Findings come from returned configuration
  facts only.
- **CLOUD_CSPM** runs the governed tools (Prowler, ScoutSuite,
  Steampipe packs, import connectors). Their observations land on the
  same canonical rules as native analysis and merge by cloud
  fingerprint (provider + account + region + resource + rule + class).
- **CLOUD_COMPLIANCE** assembles CIS control assessments through the
  Phase 13 framework, computes drift and builds risk paths.
- **QUALITY_GATE** evaluates the cloud gate; a FAILED gate is a
  recorded result, never a pipeline crash.

## Workers (§10)

Cloud adapters execute only on the `CLOUD_ANALYSIS` worker type
(docker-compose service `worker-cloud-analysis`). The executor denies
cloud adapters on any other worker (`UNAVAILABLE_FOR_WORKER`), and
denies connectors when no account context was store-resolved
(`TOOL_UNAVAILABLE` / NOT_CONFIGURED).

## Untrusted input discipline (§99)

Cloud API responses and IAM policy documents are untrusted input:
bounded JSON (10 MiB, depth 32), a hardened IAM policy parser
(256 KiB, statement/action caps), sanitized provider tags/labels, and
secret-shape redaction before anything persists. Hostile fixtures in
the test suite prove the caps and the redaction.

## Production transports

Provider transports are deployment-provisioned: the worker ships with
an intentionally empty transport map, so registered accounts honestly
report NOT_CONFIGURED until an operator wires the deployment's
read-only provider clients. Fixture transports back all verification.
