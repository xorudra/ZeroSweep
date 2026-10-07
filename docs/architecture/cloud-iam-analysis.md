# Cloud IAM Analysis (Prompt 14 §36–§42)

IAM is analyzed from **normalized identity facts**: users, roles,
groups, service accounts, managed identities and their attached
policies — across AWS IAM, Entra ID RBAC and GCP IAM with one rule
set.

## Policy documents are untrusted input (§41)

Policy JSON is parsed by a hardened parser before any analysis:
256 KiB cap, at most 100 statements and 512 actions per document,
bounded recursion. The parser extracts FACTS only — admin equivalence,
wildcard actions/resources, broad trust principals — and the facts,
not the raw document, drive findings. Malformed or oversize documents
are rejected, never partially trusted.

## Rules

| Rule | Meaning |
|---|---|
| `iam-admin-equivalent` | Identity holds admin-equivalent privilege (managed admin policy, owner role, wildcard `*` on `*`) |
| `iam-wildcard-actions` | Policy grants wildcard actions on all resources |
| `iam-broad-trust` | Trust policy allows assumption by `*` principals |
| `mfa-not-enabled` | Human user without MFA |
| `iam-long-lived-credentials` | Active access key older than the governed age |
| `iam-stale-privileged-access` | Privileged identity unused beyond the governed window |

A privilege verdict is **evidence-backed**: the identity row stores
the policy facts behind it (`privilegeEvidence`), and identity alone
is never a finding by itself.

## Credential material (§40)

Credential material itself is never collected: the inventory carries
key **age and status metadata only**. Secret values — AWS secret keys,
client secrets, service-account private keys — have no field anywhere
in the model and are never requested from provider APIs.

ROADtools contributes Entra ID role assignments and application
permissions from recorded exports, defensive analysis only (§29/§30);
offensive directory operations are never invoked (§106). Its
observations map to the same IAM rules and merge by fingerprint.
