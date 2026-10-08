# Cloud Attack Paths (Prompt 34 §32/§33)

Attack paths are CANDIDATES derived analytically from two data
sources the platform already holds: public exposure (resource
exposure + identity attachments) and the IAM graph (assumption and
grant edges). A candidate reads: public resource → attached/workload
identity → assumed privileged role → sensitive resource in reach.

## Rules

- Paths are never executed, validated by exploitation, or used to
  move laterally. `executed` is `false` on every candidate, by type.
- Every step is labelled OBSERVED (directly seen in collected data)
  or INFERRED (derived relationship). A path with any inferred step
  is "theoretical" and carries lower confidence.
- Candidates persist to `CloudRiskPath` (the Prompt 14 model) and
  feed Risk Engine prioritization — a path raises the priority of
  its constituent findings; it is not itself a scanner finding.
- The UI presents the three concepts distinctly: Observed Evidence,
  Inferred Relationship, Potential Path (§132).

Kubernetes has the parallel construction (§89): public workload →
over-privileged service account (from RBAC risks) → cluster impact,
with the same labels and the same never-executed rule.
