# Analytics Performance (Prompt 27 §118–§121/§145)

## Budgets (targets, not benchmark claims — §121)

| Surface | p95 target |
|---|---|
| Search | 750 ms |
| Finding/asset timeline | 750 ms |
| Dashboard aggregation | 1500 ms |
| Heavy aggregation | 2000 ms |

Hard bounds enforced in code: ≤1000 candidate documents per search,
≤10,000 events per store query, ≤100 export rows/page (1000 total),
graph traversal depth ≤4 / 200 nodes / 500 edges, DSL ≤32 clauses.

## Health (§118)

`GET /analytics/health` reports landed events, document count,
dead-letter volume, per-partition checkpoints, ingestion lag,
search-index lag, aggregation freshness (latest dashboard snapshot),
recent reindex jobs and alerts (`HIGH_DEAD_LETTER_RATE`,
`INGESTION_STALLED`, `SEARCH_INDEX_EMPTY`).

## Load evidence (§145)

The §145 test lands 10,000 canonical events through the real ingestion
path (validation + idempotent store + projection) and aggregates them,
asserting a generous wall-clock bound against the in-memory test double.
It is a regression guard, not a production benchmark: production landing
is a single indexed `INSERT` per event (unique `eventId`), and queries
hit the composite tenant/time indexes listed in
`docs/architecture/security-data-lake.md`.
