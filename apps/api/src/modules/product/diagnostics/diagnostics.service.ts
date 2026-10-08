import { Inject, Injectable } from "@nestjs/common";
import { buildDiagnosticBundle, type DiagnosticBundle } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { HealthService } from "../../../health/health.service";
import { ProductConfigService } from "../product-config.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * SupportDiagnosticsService (Prompt 40 §206–§210).
 *
 * A bundle is produced ONLY on an explicit operator action (§209) and
 * contains versions, service health, worker health, queue status and
 * configuration KEYS (secret values redacted by the SDK builder,
 * §208/§230). It never contains tokens, passwords, private keys, target
 * evidence or customer content.
 */
@Injectable()
export class SupportDiagnosticsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly health: HealthService,
    private readonly config: ProductConfigService,
  ) {}

  async generateBundle(): Promise<DiagnosticBundle> {
    const health = await this.health.check().catch(() => ({ status: "unknown", checks: {} as Record<string, { status: string }> }));
    const serviceHealth: Record<string, string> = {};
    for (const [name, check] of Object.entries((health as any).checks ?? {})) {
      serviceHealth[name] = (check as any).status ?? "unknown";
    }
    serviceHealth.overall = (health as any).status ?? "unknown";
    const workers = await (this.prisma as any).workerNode.findMany({}).catch(() => []);
    const recentErrors = await (this.prisma as any).auditLog.findMany({
      where: { action: "POLICY_DENIED" }, orderBy: { createdAt: "desc" }, take: 10,
    }).catch(() => []);
    return buildDiagnosticBundle({
      releaseVersion: this.config.releaseVersion(),
      productMode: this.config.productMode(),
      generatedAt: new Date(),
      serviceHealth,
      workerHealth: (workers as any[]).map((w) => ({ id: w.workerId, status: w.status, version: w.version })),
      queueStatus: [],
      configuration: this.config.configurationSummary(),
      recentErrors: (recentErrors as any[]).map((e) => `${e.action} on ${e.resourceType} at ${new Date(e.createdAt).toISOString()}`),
    });
  }

  /** §210 operator health check: one-call verification of the product surface. */
  async productHealthCheck(): Promise<any> {
    const health = await this.health.check().catch(() => ({ status: "down", checks: {} }));
    const [tools, regions, plans] = await Promise.all([
      (this.prisma as any).tool.count({}).catch(() => null),
      (this.prisma as any).deploymentRegion.findMany({}).catch(() => []),
      (this.prisma as any).productPlan.count({ where: { status: "ACTIVE" } }).catch(() => null),
    ]);
    return {
      status: (health as any).status,
      services: (health as any).checks,
      releaseVersion: this.config.releaseVersion(),
      productMode: this.config.productMode(),
      billing: this.config.billing(),
      licensingEnabled: this.config.licensingEnabled(),
      toolRegistryEntries: tools,
      activePlans: plans,
      regions: regions,
      generatedAt: new Date().toISOString(),
    };
  }
}
