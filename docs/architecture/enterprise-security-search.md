# Enterprise Security Search (Prompt 27 §19–§38)

One search across assets, findings, scans, reports, repositories,
controls, risks, tickets, audit records and security events.

## Index

`IndexingService` builds `SecuritySearchDocument` rows from tenant-scoped
operational tables. All text passes `redactForAi` **before** it can reach
`searchableText` (§25/§130) and carries a data classification
(PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED).

## Query path

1. The caller's **classification ceiling** (role-based; RESTRICTED only for
   leads/owners/engineers with `VIEW_RESTRICTED_ANALYTICS`) is applied in
   the Prisma `WHERE` — restricted documents are never retrieved for
   unauthorized users, not filtered afterwards (§28/§128).
2. Queries are parsed by the governed **Security Query DSL** (allowlisted
   fields/operators, bounded clauses/depth) or fall back to token AND-match.
   Hostile strings are inert data (§125). There is no path from user input
   to SQL — evaluation runs over typed records in memory (≤1000 candidates).
3. Results carry escaped+redacted snippets (§129), facets, group counts,
   cursor pagination, and `whyMatched` field explanations (§97).
4. Every search writes a `SECURITY_SEARCH_EXECUTED` audit event (§110).
5. Suggestions are drawn only from already-scoped documents, so they can
   never leak another tenant's names (§31/§127).

Saved queries are re-parsed on save **and** on run; PRIVATE queries are
owner-only, WORKSPACE queries are shared within the workspace (§32/§33).
