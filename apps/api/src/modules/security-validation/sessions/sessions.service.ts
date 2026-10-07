import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";

/**
 * Validation sessions (Prompt 16 §12/§57): worker execution records —
 * status, tool, validator, target, start/duration, budget consumption
 * and termination reason. Tenant-scoped by workspace on every read.
 */
@Injectable()
export class ValidationSessionsService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async listForRequest(workspaceId: string, requestId: string) {
    return this.prisma.validationSession.findMany({
      where: { requestId, workspaceId },
      orderBy: { createdAt: "desc" },
      take: 50,
      include: { evidence: { orderBy: { createdAt: "asc" }, take: 100 } },
    });
  }

  async getSession(workspaceId: string, sessionId: string) {
    const session = await this.prisma.validationSession.findFirst({
      where: { id: sessionId, workspaceId },
      include: { evidence: { orderBy: { createdAt: "asc" }, take: 200 }, request: true },
    });
    if (!session) throw new NotFoundException("validation session not found in this workspace (§94)");
    const durationSeconds = session.startedAt && session.endedAt
      ? (new Date(session.endedAt).getTime() - new Date(session.startedAt).getTime()) / 1000
      : null;
    return { ...session, durationSeconds };
  }
}
