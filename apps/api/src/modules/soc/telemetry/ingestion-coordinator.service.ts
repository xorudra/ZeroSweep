import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { TelemetryService, type IngestAuth } from "./telemetry.service";
import { DetectionService } from "../detections/detection.service";
import { IntelService } from "../threat-intelligence/intel.service";
import { SocCorrelationService } from "../correlation/soc-correlation.service";
import type { Row } from "../helpers";

/**
 * Ingestion coordinator (Prompt 28 §8): after telemetry is stored,
 * each NEW event flows through indicator matching → detection →
 * SOC correlation, in that order, so correlation patterns can see
 * the matches detection produced. Duplicates short-circuit (§11):
 * a replayed provider event produces no new matches or alerts.
 */
@Injectable()
export class IngestionCoordinator {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly telemetry: TelemetryService,
    private readonly detections: DetectionService,
    private readonly intel: IntelService,
    private readonly correlation: SocCorrelationService,
  ) {}

  async ingestAndProcess(user: RequestUser, workspaceId: string, auth: IngestAuth, rawEvents: unknown[]) {
    const result = await this.telemetry.ingest(user, workspaceId, auth, rawEvents);
    let indicatorMatches = 0;
    let detectionMatches = 0;
    let alertsCreated = 0;
    const patterns = new Set<string>();
    for (const stored of result.stored) {
      if (stored.duplicate) continue;
      const row = await this.prisma.securityTelemetryEvent.findFirst({
        where: { id: stored.id, workspaceId },
      }) as Row | null;
      if (!row) continue;
      const intel = await this.intel.matchEvent(user.organizationId, workspaceId, row);
      indicatorMatches += intel.matches;
      const detection = await this.detections.evaluateEvent(user.organizationId, workspaceId, row);
      detectionMatches += detection.matches;
      alertsCreated += detection.alertsCreated;
      const corr = await this.correlation.evaluateEventPatterns(user.organizationId, workspaceId, row);
      alertsCreated += corr.alertsCreated;
      for (const p of corr.patterns) patterns.add(p);
    }
    return {
      authMode: result.authMode,
      stored: result.stored.filter((s) => !s.duplicate).length,
      duplicates: result.duplicates,
      rejected: result.rejected,
      indicatorMatches, detectionMatches, alertsCreated,
      correlationPatterns: [...patterns],
    };
  }
}
