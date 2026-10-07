# Cloud Read-Only Policy (Prompt 14 §7/§106)

Assessment of cloud accounts is **read-only, permanently**. This is a
product invariant, not a configuration option.

## What the platform does

- Registers accounts as verified targets and records identity,
  scope and a credential **reference** (see
  [cloud-credential-model](cloud-credential-model.md)).
- Requests read-only access: provider transports call
  Describe/Get/List-class APIs only. The transport interface has **no
  mutating method** — read-only is enforced by construction, and the
  §93 test fails if a transport ever records a mutation call.
- Analyzes returned configuration data: findings, compliance
  evidence, drift observations and risk-path models.
- Produces remediation **guidance** (deterministic text/snippets in
  findings and reports). Guidance is advice to the account owner —
  it is never applied by the platform.

## What the platform never does

- Create, modify or delete any cloud resource, policy, rule or tag.
- Remediation actions of any kind against an account.
- Privilege escalation, exploitation or offensive testing — Pacu is
  registered **DISABLED** for exactly this reason (§34): no adapter,
  no execution path, no stage can select it.
- Ask for or store write-capable credentials: the credential model
  accepts reference names only, and assessment roles are expected to
  be read-only on the provider side.
- Retrieve secret values, object contents, key material or database
  rows (§13/§40/§43/§52/§53/§55). Metadata only.

## Enforcement points

- `CloudAccount.assessmentPolicy` is `READ_ONLY` — the only posture.
- Executor capability gate: cloud adapters run only on the
  `CLOUD_ANALYSIS` worker.
- SDK config validation rejects credential-like keys and inline
  secrets in every cloud adapter's configuration.
- SSRF policy on any endpoint the platform is configured with (§101):
  metadata endpoints and private addresses are denied; HTTPS only for
  provider management endpoints.
