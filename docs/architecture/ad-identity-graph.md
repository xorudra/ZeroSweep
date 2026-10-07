# The AD Identity Graph (Prompt 15 §32–§37)

The identity graph is the analytical core of the AD assessment. It is
built exclusively from **collected evidence**: every edge carries
provenance — the source tool/connector, a confidence
(`HIGH`/`MEDIUM`/`LOW`) and an optional evidence reference (§33). The
platform never speculates an edge into existence.

## Nodes and edges

Nodes are users, groups, computers, domain controllers, OUs, GPOs,
trust targets, CAs and certificate templates. Edges include
`MEMBER_OF`, ACL grants (`GENERIC_ALL`, `GENERIC_WRITE`, `WRITE_DACL`,
`WRITE_OWNER`, `OWNS`), `ADMIN_TO`, `CAN_RDP`, `HAS_SESSION`,
delegation and trust relationships. Session and local-admin edges are
sensitive (§69): they enter the graph only when the collection policy
approved those SharpHound method classes (§29); otherwise they are
dropped at parse time and the drop is counted, never silent.

## Nested groups and cycles

Effective membership resolves nested groups with an iterative,
visited-set fixpoint (§65/§108): cycles (group A ↔ group B) are
detected, counted and terminate; expansion is depth- and
count-bounded against hostile or pathological data.

## Privilege classification

A group's privilege class derives from its **SID/RID** by policy
(Domain Admins 512, Enterprise Admins 519, Schema Admins 518,
Administrators 544 are PRIVILEGED; account/backup/server/print
operators and policy creators are HIGH_IMPACT) — never from the
display name, which is attacker-controlled text (§59). A principal is
privileged only with evidence: effective membership in a privileged
group, a high-impact ACL over a critical object, or an equivalent
recorded grant; the evidence travels with the annotation (§60).

## Explainable risk

Users, computers and paths carry explainable risk (§77/§78): named
factors with points, an annotation that states why. Risk ranking for
attack paths combines target criticality, privilege gain, edge
confidence, evidence quality and path length — explicitly **not**
shortest-path (§37).
