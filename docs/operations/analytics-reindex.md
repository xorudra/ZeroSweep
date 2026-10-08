# Analytics Reindex (Prompt 27 §117/§144)

`POST /analytics/reindex` (or `POST /analytics/index` for an additive
refresh) rebuilds `SecuritySearchDocument` rows for one workspace:

1. A `SecuritySearchReindexJob` row is created (status RUNNING).
2. Existing documents **for that workspace only** are deleted.
3. Documents are rebuilt through the same indexing path used everywhere
   (same redaction, same facets, same classification).
4. The job completes with the rebuilt document count; permissions and
   tenant scope are properties of the rebuild inputs, so they are
   preserved by construction (§144).

Reindexing is safe to run at any time and is the recovery path for index
schema changes. It never touches another workspace's documents.
