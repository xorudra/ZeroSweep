# AI tenant isolation (Prompt 21 §12, §58, §61, §94, §96)

Isolation is enforced at four independent layers, so no single
failure — including a successful prompt injection — can cross
workspaces:

1. **Data layer (§12).** Every context loader, NL row load, vector
   search and conversation query carries `workspaceId` in its `where`
   clause. Cross-tenant ids resolve to 404/not-found.
2. **Citations.** The pipeline persists only citations referencing
   records that came from the caller's context; grounded answers cite
   those ids, so an answer can be audited to prove which workspace's
   records produced it.
3. **Cache (§76).** The cache key binds tenant + task + context hash
   + model + policy + data version — a response can never be replayed
   across tenants or across a policy change.
4. **Vectors (§96).** `AiEmbedding` rows carry `workspaceId`; search
   filters on it **before** similarity ranking.

## Tests (§94)

- Explaining another workspace's finding → 404, zero request logs
  created.
- NL search results never include foreign-workspace rows even when
  they match the DSL better.
- Vector search in workspace A returns no hits from workspace B
  embeddings with identical content.
- Conversations are listed per (workspace, user) — another user's or
  tenant's conversation is not retrievable.

## Prompt 36 additions (§12/§105/§164)

V2 adds two more independent layers on top of the four above:

5. **Retrieval filter.** The SDK retrieval choke point
   (`filterRetrievalCandidates`) drops any candidate whose
   workspaceId differs from the request workspace, recording the
   reason; candidates are never re-homed into another tenant's
   context. Per-source permissions and classification ceilings are
   enforced in the same pass, and skipped sources are disclosed.
6. **Plan layer.** The planner's authorization snapshot is built
   from the request workspace only and plans bind its hash; the
   deterministic validator rejects target references outside the
   snapshot (§107), and execution re-validates against the current
   snapshot (§150).

Memory is per (workspace, user) (§95); traces, approvals, workflows
and evaluations are workspace-scoped rows. The §105 red-team case
and API-level isolation tests exercise all layers in CI.
