# Natural-language security search (Prompt 21 §41–§45, §95)

## Architecture (§42)

```
question → intent parser → TYPED QUERY PLAN (SecurityQueryDSL)
         → authorization (§116 AI_QUERY_SECURITY_DATA)
         → plan validator (§44)
         → tenant-filtered row load (§12)
         → pure DSL executor
         → results + finding-id citations (§45)
```

There is **no** path from a question to AI-generated SQL. The parser
is deterministic and closed: it recognizes severities, verification
state, KEV, overdue, production environment, domains, limits and
sorting, and nothing else. Unmappable questions get a clarification
refusal; SQL-shaped input (`UNION SELECT`, `DROP TABLE`, tautologies,
comment/terminator sequences) is rejected outright and audited as a
policy block (§95).

## DSL (§43/§44)

Plans contain only: `severityIn`, `verificationStatus`, `kevOnly`,
`lifecycleStatusIn`, `domainIn`, `environment`, `overdueOnly`,
`textSearch`, `sortField` (riskScore | createdAt), `sortDirection`,
`groupBy` (severity | domain | status) and `limit`. The validator
bounds the limit against the workspace retrieval cap and rejects
unknown fields/values before execution.

## Citations (§45)

Every result row is a real finding of the caller's workspace; the
response carries one FINDING citation per row, so NL answers are
auditable to the same standard as copilot explanations.
