# ScoutSuite Adapter (Prompt 14 §26)

## Purpose
Multi-cloud security auditing (NCC Group ScoutSuite) for AWS, Azure
and GCP, run as a governed CLI adapter on the CLOUD_ANALYSIS worker.

## Capabilities
`CSPM`, `CLOUD_POSTURE`

## Supported target types
AWS, AZURE, GCP (registered cloud accounts)

## Risk level
LOW — read-only auditing over a credential reference.

## Execution mode
CONTAINER. Argument array only: `scout <aws|azure|gcp> --no-browser`.
No user-supplied flags.

## Required configuration
Worker-derived only: `cloudAccountId`, `cloudAccountRef`,
`cloudProvider`, `credentialReference` (name only).

## Output handling
Rule results (`danger`/`warning` findings in the ScoutSuite report)
map onto the **canonical cloud rules** shared with Prowler and the
native analyzers, and merge by cloud fingerprint — the same public
bucket reported by all three sources is ONE canonical finding with
three observations (§60/§95). Services absent from the report
contribute nothing; nothing is inferred.
