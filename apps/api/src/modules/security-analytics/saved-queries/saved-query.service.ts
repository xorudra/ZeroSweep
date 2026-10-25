import { ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { parseSecurityQueryDsl } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireAnalyticsPermission } from "../permissions";
import { SearchService } from "../search/search.service";

/**
 * Saved security queries (§32/§33). The stored DSL is re-parsed on
 * every save and every run — stored text is never trusted blind.
 * PRIVATE queries belong to their author; WORKSPACE visibility
 * requires the SEARCH_SECURITY permission to share.
 */
@Injectable()
export class SavedQueryService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly search: SearchService,
  ) {}

  async create(user: RequestUser, workspaceId: string, body: { name: string; queryText: string; filters?: Record<string, unknown>; visibility?: string }) {
    const parsed = parseSecurityQueryDsl(body.queryText);
    if ("rejected" in parsed) throw new ForbiddenException(`Query rejected: ${parsed.rejected}`);
    if (body.visibility === "WORKSPACE") requireAnalyticsPermission(user, "SEARCH_SECURITY");
    return this.prisma.savedSecurityQuery.create({
      data: {
        workspaceId, userId: user.id, name: body.name, queryText: body.queryText,
        filters: (body.filters ?? {}) as never, visibility: body.visibility ?? "PRIVATE",
      },
    });
  }

  async list(user: RequestUser, workspaceId: string) {
    const rows = await this.prisma.savedSecurityQuery.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200,
    });
    // Visibility enforced in the service: private = owner only (§33).
    return rows.filter((r) => r.visibility === "WORKSPACE" || r.userId === user.id);
  }

  async remove(user: RequestUser, workspaceId: string, id: string) {
    const row = await this.prisma.savedSecurityQuery.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Saved query not found");
    if (row.userId !== user.id && user.role !== "OWNER" && user.role !== "ADMIN") {
      throw new ForbiddenException("Only the query owner or an admin may delete a saved query");
    }
    await this.prisma.savedSecurityQuery.delete({ where: { id } });
    return { deleted: true };
  }

  async run(user: RequestUser, workspace: { id: string }, id: string) {
    const rows = await this.list(user, workspace.id);
    const row = rows.find((r) => r.id === id);
    if (!row) throw new NotFoundException("Saved query not found");
    const parsed = parseSecurityQueryDsl(row.queryText);
    if ("rejected" in parsed) throw new ForbiddenException(`Stored query no longer parses: ${parsed.rejected}`);
    return this.search.search(user, workspace, { query: row.queryText, pageSize: 25 });
  }
}
