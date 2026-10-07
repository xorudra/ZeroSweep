# Prowler Adapter (Prompt 14 §23/§24)

## Purpose
Multi-cloud CSPM checks (CIS/posture) for AWS, Azure and GCP, run as a
governed CLI adapter on the CLOUD_ANALYSIS worker.

## Capabilities
`CSPM`, `CLOUD_POSTURE`, `COMPLIANCE_QUERY`

## Supported target types
AWS, AZURE, GCP (registered cloud accounts)

## Risk level
LOW — read-only checks over a credential reference.

## Execution mode
CONTAINER. Argument array only: `prowler <aws|azure|gcp>
--output-formats json --no-banner --log-level ERROR`. No user-supplied
flags; exit code 3 (checks failed) is an acceptable result, not a
tool failure.

## Required configuration
Worker-derived only: `cloudAccountId`, `cloudAccountRef`,
`cloudProvider`, `credentialReference` (name only). Inline secrets or
credential-like keys are rejected by SDK config validation (§6).

## Output handling
FAIL results become findings on the **canonical cloud rules** (e.g.
`s3_bucket_public_access → storage-public-access`), so a Prowler
observation merges by cloud fingerprint with ScoutSuite and native
analysis of the same issue (§60/§95). **PASS results are posture
evidence only — never findings** (§23). Unparseable output yields no
findings, never fabricated ones.
