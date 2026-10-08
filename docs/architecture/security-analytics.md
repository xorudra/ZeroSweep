# Security Analytics (Prompt 27)

Analytics are computed **only over real platform records**. There is no
synthetic series, interpolation or demo data anywhere in the layer: an
empty workspace returns empty distributions, `null` means (MTTR with no
resolved findings), and "not computable" deltas (previous period = 0).

## Computation model

- Pure aggregation functions live in `@dsrclone/security-sdk`
  (`analytics/`): `timeSeries`, `groupCount`, `topN`, `distribution`,
  `percentile`, `trend`, lifecycle projection, SLA buckets. They are
  deterministic and unit-tested; the API layer only fetches tenant-scoped
  rows and calls them.
- Every dashboard response names its **source tables** (`sources: [...]`),
  so every number is reproducible from a stated query over stated tables.
- Time ranges are explicit (default 90 days); bucketing is
  `bucketForRange` (day/week/month by span).

## Surfaces (§98–§101)

`GET /analytics/overview|findings|assets|risk|devsecops|cloud|identity|grc`,
attack-surface dashboard, asset/finding timelines, correlation signals,
attack paths, saved queries, exports, retention and health — all behind
role permissions (`VIEW_ANALYTICS`, `SEARCH_SECURITY`, `EXPORT_ANALYTICS`,
`VIEW_ATTACK_PATHS`, `MANAGE_ANALYTICS`, `VIEW_RESTRICTED_ANALYTICS`).

## Caching (§122)

Aggregation responses may be cached briefly (60 s) under a key that binds
organization + workspace + role + permission fingerprint + classification
ceiling + view + filters (`analyticsCacheKey`). A cache entry is therefore
unreachable from any other tenant or security context (§142); tenant-tag
invalidation drops a workspace's entries on ingestion/reindex.
