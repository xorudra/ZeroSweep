# Cloud IAM Security (Prompt 34 §28–§31)

IAM analysis runs over collected identity metadata only — policies
are parsed with the Prompt 14 hardened parser (never executed),
trust relationships are read as data, and no identity is ever
assumed, logged in as, or used by the platform.

## Posture signals (§28)

`analyzeCloudIamPosture` emits typed signals: OVERLY_BROAD_PERMISSIONS
(wildcard actions/resources or AdministratorAccess), PUBLIC_ACCESS
(principal `*`), DANGEROUS_TRUST (external account with no condition),
MISSING_MFA_EVIDENCE (only on an explicit MFA-absent statement —
absence of evidence is not a finding), LONG_LIVED_CREDENTIAL
(access key older than 365 days), STALE_PRIVILEGED (privileged and
inactive > 90 days), UNUSED_PRIVILEGED (privileged and explicitly
never used).

## Graph (§30)

`buildIamGraphEdges` derives ASSUMES / CAN_ASSUME / GRANTS / TRUSTS /
RUNS / ATTACHED_TO edges from declared metadata (assumesRoles,
accessibleResources, attachedIdentity). Edges persist to
`CloudRelationship` during assessment. The graph answers who can
assume what and what a privileged identity can reach — as evidence,
not as an action surface.
