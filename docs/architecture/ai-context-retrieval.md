# AI context & retrieval (Prompt 21 §9–§13, §40, §66–§68)

## Least-context principle (§10)

The `SecurityContextBuilder` assembles the minimal record set for the
task: the finding's structured core, its description (UNTRUSTED),
observations and evidence summaries (capped), the affected asset,
Risk Engine V3's stored signals, and intel records (CVE/CWE/EPSS/KEV)
when the finding references them. A code snippet is included only
for code-oriented tasks and is capped at 2,000 chars (§33). Context
is size-estimated and trimmed lowest-priority-first — UNTRUSTED
records go before TRUSTED ones, and mandatory policy text is never
trimmed (§106).

## Authorization order (§11/§12)

1. The API checks the task's §116 permission **before** any record is
   loaded.
2. Every loader query carries `workspaceId` — tenant filtering at the
   data layer, never via prompt instructions. Another tenant's record
   is indistinguishable from a nonexistent one (404).
3. Only then does the builder run. The model cannot receive records
   the requester cannot access.

## Classification (§13)

Records are classified PUBLIC (intel reference data), INTERNAL
(structured platform fields), CONFIDENTIAL (scanner/evidence text,
code), RESTRICTED/SECRET by caller marking. The context's maximum
classification drives task policy: SECRET never goes to an external
provider (§14); anything above a provider's approved classifications
is denied (§64).

## Graph context (§40)

Attack-path explanation consumes the defensive P15 graph model
through the same finding-context path (typed, read-only); the AI
explains entry points, privilege transitions and mitigations — it
never executes a path (§39).

## Embeddings & vectors (§66–§68)

`SecurityEmbeddingService` uses a deterministic local hashing
embedder (lexical, offline, reproducible — honestly not a neural
semantic model). Every vector row stores `workspaceId`, `sourceType`,
`sourceId` and `classification`. Retrieval filters on that metadata
**before** ranking by similarity, and applies the classification
ceiling before ranking too — isolation is a property of the filter,
not of the similarity score (§68/§96). Raw secrets are never embedded
(§69): knowledge content is redacted at ingestion (§72).
