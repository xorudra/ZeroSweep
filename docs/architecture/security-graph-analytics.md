# Security Graph Analytics (Prompt 27 §83–§87)

The security graph is built on demand from tenant-scoped records:
assets, services, findings, repositories and images, with edges such as
`HOSTS`, `RUNS`, `HAS_FINDING`, `DEPENDS_ON`, `SAME_NETWORK`, `CONTAINS`.

- Every edge carries an **evidence reference** (the record id it came
  from). Edges without evidence are not emitted.
- Traversal is bounded: depth ≤ 4, nodes ≤ 200, edges ≤ 500 by default;
  requests beyond the hard limits are **rejected**, not truncated
  silently (§139).
- Graph construction is read-only and tenant-scoped in the query layer —
  a node from another workspace cannot appear, so paths cannot cross
  tenants.
