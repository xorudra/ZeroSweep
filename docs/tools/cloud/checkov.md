# Checkov in Cloud Security (Prompt 14 §33/§62)

Checkov is **shared** with the cloud-native family (Prompt 13): one
adapter serves Kubernetes/Dockerfile/Helm/IaC static analysis there
and IaC↔cloud correlation here. It is not re-implemented for
Prompt 14.

## Role in this phase

In `IAC_TO_CLOUD_CORRELATION` and `CLOUD_COMPREHENSIVE` scans, the
`MANIFEST_SCAN` stage runs Checkov over the governed IaC inputs. Its
observations (`STATIC_CONFIGURATION_FINDING`) correlate with live
inventory findings under the conservative §62 rule:

1. the Checkov check id must map to a live cloud rule through the
   governed mapping (e.g. `CKV_AWS_53 → storage-public-access`), and
2. the resource identity must match reliably — the Terraform address's
   resource name equals the deployed resource's name.

When both hold, the static and live observations merge into one
canonical finding; when they disagree, a `IAC_DRIFT` event records the
mismatch (see [cloud-drift](../../architecture/cloud-drift.md)).
Unmapped rules never merge.

## Discipline

IaC is never executed, applied or planned against a live account —
Checkov reads source only (Prompt 12/13 intake discipline), and its
output is parsed as untrusted input under the hardened importer.
