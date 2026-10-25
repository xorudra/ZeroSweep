import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import {
  DEFAULT_SLOS, evaluateSli, validateReleaseMetadata,
  type SliResult, type SloDefinition,
} from "@zerosweep/security-sdk";
import { loadEnv } from "@zerosweep/config";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { AuditService } from "../audit/audit.service";
import { HealthService } from "../../health/health.service";
import { QueueService } from "../../queue/queue.service";
import { PlatformControlService } from "./platform-control.service";
import { ProductionConfigurationService } from "./production-config.service";
import { requirePlatformPermission } from "./permissions";

/**
 * Platform overview (Prompt 38 §197–§200): one honest aggregate for the
 * admin plane — service health, release identity, dependency status,
 * queue backlogs, worker pools (heartbeat-derived), storage, backups,
 * deployments and SLO evaluations. Every number comes from a live
 * check or a persisted row; anything unmeasured is reported as such
 * (§127/§238) — this service invents nothing.
 */
@Injectable()
export class PlatformOverviewService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly health: HealthService,
    private readonly queue: QueueService,
    private readonly control: PlatformControlService,
    private readonly productionConfig: ProductionConfigurationService,
  ) {}

  async overview(user: RequestUser) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    const env = loadEnv();
    const [health, control, queues, workers, latestBackup, latestDeployment] = await Promise.all([
      this.health.check(),
      this.control.getState(),
      this.queue.adminSnapshot().catch(() => []),
      this.listWorkers(user),
      this.prisma.platformBackup.findFirst({ orderBy: { startedAt: "desc" } }),
      this.prisma.platformDeployment.findFirst({ orderBy: { startedAt: "desc" } }),
    ]);
    return {
      status: health.status,
      checks: health.checks,
      release: {
        version: env.RELEASE_VERSION ?? "dev",
        commit: env.GIT_COMMIT ?? "unknown",
        environment: env.NODE_ENV,
        recordedDeployment: latestDeployment
          ? { version: latestDeployment.version, commit: latestDeployment.commit, status: latestDeployment.status, migrationVersion: latestDeployment.migrationVersion, startedAt: latestDeployment.startedAt }
          : null,
      },
      control,
      productionConfig: this.productionConfig.evaluate(),
      queues,
      workers: workers.items,
      storage: {
        endpoint: env.MINIO_ENDPOINT,
        status: health.checks.minio?.status ?? "skipped",
        note: health.checks.minio?.status === "ok"
          ? "S3-compatible object storage reachable"
          : "object storage not reachable from this instance — artifact flows that require it report unavailable, never fake success",
      },
      ai: { status: health.checks.ai?.status ?? "skipped", serviceUrl: env.AI_SERVICE_URL },
      backups: {
        latest: latestBackup
          ? { id: latestBackup.id, kind: latestBackup.kind, status: latestBackup.status, startedAt: latestBackup.startedAt, encrypted: latestBackup.encrypted }
          : null,
      },
      generatedAt: new Date().toISOString(),
    };
  }

  /** §199: worker registry with heartbeat-derived status. A worker is
   *  STALE after 2 missed minutes, OFFLINE after 10 — status is derived
   *  from the heartbeat, never trusted from the row (§48). */
  async listWorkers(user: RequestUser) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    const rows = await this.prisma.workerNode.findMany({ orderBy: { lastHeartbeat: "desc" }, take: 100 });
    const now = Date.now();
    const items = rows.map((w) => {
      const ageMs = now - new Date(w.lastHeartbeat).getTime();
      const derived = ageMs <= 120_000 ? "ONLINE" : ageMs <= 600_000 ? "STALE" : "OFFLINE";
      return {
        id: w.id, workerId: w.workerId, hostname: w.hostname, version: w.version,
        workerType: w.workerType, capabilities: w.capabilities, activeJobs: w.activeJobs,
        status: derived, heartbeatAgeMs: ageMs, lastHeartbeat: w.lastHeartbeat,
      };
    });
    return { items };
  }

  async queues(user: RequestUser) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    return { items: await this.queue.adminSnapshot() };
  }

  async failedJobs(user: RequestUser, queueName: string) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    return { items: await this.queue.adminFailedJobs(queueName) };
  }

  async retryJob(user: RequestUser, queueName: string, jobId: string) {
    requirePlatformPermission(user, "MANAGE_QUEUES");
    const result = await this.queue.adminRetryJob(queueName, jobId);
    if (!result.ok) throw new BadRequestException(result.reason);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: "QUEUE_JOB_RETRIED", resourceType: "QueueJob", resourceId: jobId,
      metadata: { queue: queueName, kind: result.kind ?? "unknown" },
    });
    return result;
  }

  async cancelJob(user: RequestUser, queueName: string, jobId: string) {
    requirePlatformPermission(user, "MANAGE_QUEUES");
    const result = await this.queue.adminCancelJob(queueName, jobId);
    if (!result.ok) throw new BadRequestException(result.reason);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: "QUEUE_JOB_CANCELLED", resourceType: "QueueJob", resourceId: jobId,
      metadata: { queue: queueName, kind: result.kind ?? "unknown" },
    });
    return result;
  }

  /** §124–§127: SLO definitions live in the DB (defaults seeded on
   *  first read); status is evaluated from measured rows only. */
  async listSlos(user: RequestUser): Promise<{ items: Array<SloDefinition & { result: SliResult }> }> {
    requirePlatformPermission(user, "VIEW_PLATFORM_METRICS");
    let defs = await this.prisma.serviceLevelObjective.findMany({ where: { enabled: true }, orderBy: { name: "asc" } });
    if (defs.length === 0) {
      for (const d of DEFAULT_SLOS) {
        await this.prisma.serviceLevelObjective.create({
          data: { name: d.name, kind: d.kind, target: d.target, windowDays: d.windowDays, enabled: true },
        });
      }
      defs = await this.prisma.serviceLevelObjective.findMany({ where: { enabled: true }, orderBy: { name: "asc" } });
    }
    const items = [];
    for (const def of defs) {
      const samples = await this.samplesFor(def.kind, def.windowDays);
      items.push({
        name: def.name, kind: def.kind as SloDefinition["kind"], target: def.target, windowDays: def.windowDays,
        result: evaluateSli({ name: def.name, kind: def.kind as SloDefinition["kind"], target: def.target, windowDays: def.windowDays }, samples),
      });
    }
    // §124/§127: SLO kinds with no persisted measurement source on
    // this platform (API availability probes, report-generation
    // timings) are REPORTED as INSUFFICIENT_DATA with a null ratio —
    // never silently omitted, and never given an invented figure.
    for (const unmeasured of [
      { name: "API availability (30d)", kind: "API_AVAILABILITY", target: 0.999, windowDays: 30 },
      { name: "Report generation (30d)", kind: "REPORT_GENERATION", target: 0.95, windowDays: 30 },
    ] as const) {
      if (!items.some((i) => i.kind === unmeasured.kind)) {
        items.push({ ...unmeasured, result: evaluateSli(unmeasured, { successes: 0, total: 0 }) });
      }
    }
    return { items };
  }

  private async samplesFor(kind: string, windowDays: number): Promise<{ successes: number; total: number }> {
    const since = new Date(Date.now() - windowDays * 86_400_000);
    if (kind === "BACKUP_SUCCESS") {
      const [ok, failed] = await Promise.all([
        this.prisma.platformBackup.count({ where: { status: "COMPLETED", startedAt: { gte: since } } }),
        this.prisma.platformBackup.count({ where: { status: "FAILED", startedAt: { gte: since } } }),
      ]);
      return { successes: ok, total: ok + failed };
    }
    if (kind === "RESTORE_TEST_SUCCESS") {
      const [ok, failed] = await Promise.all([
        this.prisma.platformRestore.count({ where: { status: "COMPLETED", isRestoreTest: true, startedAt: { gte: since } } }),
        this.prisma.platformRestore.count({ where: { status: "FAILED", isRestoreTest: true, startedAt: { gte: since } } }),
      ]);
      return { successes: ok, total: ok + failed };
    }
    if (kind === "SCAN_COMPLETION") {
      const [ok, failed] = await Promise.all([
        this.prisma.scan.count({ where: { status: "COMPLETED", createdAt: { gte: since } } }),
        this.prisma.scan.count({ where: { status: "FAILED", createdAt: { gte: since } } }),
      ]);
      return { successes: ok, total: ok + failed };
    }
    // API_AVAILABILITY / REPORT_GENERATION have no persisted measurement
    // source yet — evaluateSli turns zero samples into INSUFFICIENT_DATA.
    return { successes: 0, total: 0 };
  }

  /** §147/§156: deployment records. Recording is an operator act; the
   *  record is evidence, and rollback is recorded as its own event. */
  async recordDeployment(user: RequestUser, input: {
    version?: string; commit?: string; build?: string; migrationVersion?: string;
    environment?: string; notes?: string; rollback?: boolean;
  }) {
    requirePlatformPermission(user, "MANAGE_DEPLOYMENTS");
    const problems = validateReleaseMetadata({
      version: input.version, commit: input.commit, environment: input.environment ?? loadEnv().NODE_ENV,
    });
    if (problems.length) throw new BadRequestException(problems.join("; "));
    const status = input.rollback ? "ROLLBACK_STARTED" : "COMPLETED";
    const record = await this.prisma.platformDeployment.create({
      data: {
        version: input.version!, commit: input.commit!, build: input.build,
        migrationVersion: input.migrationVersion, environment: input.environment ?? loadEnv().NODE_ENV,
        status, notes: input.notes, deployedById: user.id, completedAt: new Date(),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: input.rollback ? "PRODUCTION_ROLLBACK_STARTED" : "PRODUCTION_DEPLOYMENT_COMPLETED",
      resourceType: "PlatformDeployment", resourceId: record.id,
      metadata: { version: record.version, commit: record.commit, environment: record.environment },
    });
    return record;
  }

  async listDeployments(user: RequestUser) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    const items = await this.prisma.platformDeployment.findMany({ orderBy: { startedAt: "desc" }, take: 25 });
    return { items };
  }

  async recordDrExercise(user: RequestUser, input: {
    scenario?: string; measuredRpoSeconds?: number; measuredRtoSeconds?: number;
    targetRpoSeconds?: number; targetRtoSeconds?: number; issues?: string;
  }) {
    requirePlatformPermission(user, "MANAGE_DEPLOYMENTS");
    if (!input.scenario) throw new BadRequestException("a DR exercise record requires the scenario that was exercised (§235)");
    return this.prisma.platformDrExercise.create({
      data: {
        scenario: input.scenario,
        measuredRpoSeconds: input.measuredRpoSeconds, measuredRtoSeconds: input.measuredRtoSeconds,
        targetRpoSeconds: input.targetRpoSeconds, targetRtoSeconds: input.targetRtoSeconds,
        issues: input.issues, runById: user.id,
      },
    });
  }
}
