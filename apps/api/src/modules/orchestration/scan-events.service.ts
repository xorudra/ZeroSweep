import { Inject, Injectable } from "@nestjs/common";
import { Subject } from "rxjs";
import type { ScanEventRecord } from "@zerosweep/orchestration";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";

/**
 * Durable scan events (Prompt 4 §40–§41, §55). Every lifecycle event is
 * persisted to ScanEvent FIRST (source of truth + timeline API); the in-process
 * subject only feeds the SSE presentation stream for events raised inside the
 * API process. Worker-raised events reach clients through the same durable
 * table via the events endpoint — the stream never invents state.
 */
@Injectable()
export class ScanEventsService {
  private readonly subject = new Subject<ScanEventRecord>();

  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async record(event: ScanEventRecord): Promise<void> {
    await this.prisma.scanEvent.create({
      data: { scanId: event.scanId, workspaceId: event.workspaceId, type: event.type, payload: event.payload as never },
    });
    this.subject.next(event);
  }

  /** Stream for one scan. Callers MUST authorize the scan against the
   *  caller's workspace before subscribing (§41); the controller additionally
   *  filters events to this scan id, so no cross-scan data can leak. */
  streamFor(_scanId: string) {
    return this.subject.asObservable();
  }

  async list(scanId: string, page: number, pageSize: number) {
    const [items, total] = await Promise.all([
      this.prisma.scanEvent.findMany({ where: { scanId }, orderBy: { createdAt: "asc" }, skip: (page - 1) * pageSize, take: pageSize }),
      this.prisma.scanEvent.count({ where: { scanId } }),
    ]);
    return { items, total, page, pageSize };
  }
}
