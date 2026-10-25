# Defensive Attack-Path Analysis (Prompt 15 §34–§37)

Attack paths in ZeroSweep are **computed models over collected
directory data** — nothing more. They answer the defender's question
"which principals can reach high-value targets through recorded
privilege relationships, and what should we fix first?"

## Hard rules

- A path is **never executed**. No step is authenticated, replayed or
  validated against a live system (§35).
- Path status is one of `THEORETICAL`, `EVIDENCE_BACKED`, `REVIEWED`,
  `MITIGATED`. The status **`COMPROMISED` does not exist** in the
  data model, the engine or the API (§35).
- A path never implies a principal or system is compromised (§75):
  blast-radius output carries that framing verbatim.
- Paths traverse **privilege edges only** (membership in privileged
  groups, dangerous ACLs, local-admin/RDP grants, delegation).
  Ordinary group membership is context, not a path step.

## Computation

Paths are found by bounded reverse reachability from high-value
targets (domain controllers, privileged groups, Tier-0 computers)
over the identity graph, honouring the stage budget
(`maxGraphDepth`, `maxAttackPaths`, §87). A path is
`EVIDENCE_BACKED` only when every edge on it is HIGH confidence;
otherwise it stays `THEORETICAL`. Risk scoring (§37) weighs target
criticality (DC 40 / privileged group 35 / critical computer 30),
privilege gain, the weakest edge's confidence and a mild length
penalty, and emits the named factors with the score so an analyst can
see exactly why a path ranks where it does.

## Presentation

The attack-paths page is display-only by design: there is no execute,
validate or exploit control for a path anywhere in the product. The
useful action on a path is remediation of its first edge — guided by
the finding attached to that edge (§82 guidance only; the platform
never modifies the directory, §83).
