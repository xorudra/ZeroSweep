# Database ownership

- One Prisma schema, owned by `packages/database/prisma/schema.prisma`.
  No service keeps a competing schema.
- The API is the writer for business entities; workers write scan execution
  results through the same schema. The web app never touches the database.
- Every tenant-owned row is reachable from an Organization → Workspace chain;
  queries are workspace-scoped in services (see `apps/api/src/common/tenant.ts`).
- Large artifacts (raw scanner output, screenshots, evidence, reports) live in
  object storage; Postgres stores only locations, checksums and metadata.
- Credentials table stores metadata + `secretReference` only.
- Soft deletion (`deletedAt`) on User/Organization/Workspace/Target.
- Initial migration SQL was generated with `prisma migrate diff` where no local
  database was available; run `pnpm db:migrate` against your dev database to
  apply/create migrations normally.
