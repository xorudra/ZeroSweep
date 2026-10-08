# Analytics Query Security (Prompt 27 §34–§38/§125/§126)

The query layer is injection-proof **by construction**:

- User input is parsed into a typed DSL AST by the SDK parser:
  allowlisted fields and operators only, ≤512 chars, ≤32 clauses,
  depth ≤5. Anything else is rejected with a machine-readable reason and
  the input falls back to inert token search.
- The AST is **evaluated over plain records in memory**. No string from
  the user is ever concatenated into SQL, Prisma `where` objects are
  built only from server-side constants and the caller's scope, and
  there is no raw-SQL endpoint anywhere in the module.
- Natural-language questions are translated by a deterministic parser
  into the same DSL (`translateNlToDsl`); SQL-shaped input is rejected,
  never executed (§108). There is no AI-generated SQL in the platform.
- Sort keys, page sizes and export formats are zod-validated enums with
  hard caps (search ≤100 results/page over ≤1000 candidates; export
  ≤1000 rows).

Tests: DSL injection strings return no results and no error (§125 text
path); unknown fields are rejected on saved-query save and run.
