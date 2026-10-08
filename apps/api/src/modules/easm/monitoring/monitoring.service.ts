import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireEasmPermission } from "../permissions";
import { EasmDiscoveryService } from "../discovery/discovery.service";

type Row = Record<string, unknown>;

/**
 * Continuous EASM (Prompt 29 §86–§88), riding the Prompt 22
 * scheduler: each monitoring-enabled program gets a SecuritySchedule
 * row of kind EASM_DISCOVERY (visible in the existing scheduler UI),
 * and the operator tick materializes due programs into discovery
 * runs — the same no-hidden-daemon discipline as P22. Tiers:
 * HOURLY_LIGHT = DNS/HTTP/certificate sources only; DAILY = the
 * program's full passive policy; WEEKLY_DEEP = full policy including
 * historical URLs. Expensive adapters never run hourly by default.
 * Discovery-class only: a tick can never authorize or scan anything.
 */
@Injectable()
export class EasmMonitoringService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly discovery: EasmDiscoveryService,
  ) {}

  static tierExpression(tier: string): string {
    switch (tier) {
      case "HOURLY_LIGHT": return "0 * * * *";
      case "WEEKLY_DEEP": return "0 3 * * 1";
      default: return "0 2 * * *"; // DAILY
    }
  }

  static tierSources(tier: string): string[] | undefined {
    if (tier === "HOURLY_LIGHT") return ["DNS_RESOLUTION", "DNS_ZONE_OBSERVATION", "CERT_TRANSPARENCY", "TLS_HANDSHAKE", "HTTP_PROBE"];
    return undefined; // DAILY / WEEKLY_DEEP: full policy selection
  }

  /** Ensure the P22 schedule row exists for a monitoring program. */
  async ensureSchedule(user: RequestUser, workspaceId: string, programId: string) {
    requireEasmPermission(user, "MANAGE_EASM");
    const program = await this.prisma.easmProgram.findFirst({ where: { id: programId, workspaceId } });
    if (!program) throw new Error("EASM program not found");
    const name = `EASM discovery: ${program.name as string}`;
    const existing = await this.prisma.securitySchedule.findFirst({ where: { workspaceId, kind: "EASM_DISCOVERY", name } });
    const expression = EasmMonitoringService.tierExpression(program.monitoringTier as string);
    if (existing) {
      return this.prisma.securitySchedule.update({
        where: { id: existing.id as string },
        data: { expression, enabled: program.monitoringEnabled as boolean, frequency: program.monitoringTier === "HOURLY_LIGHT" ? "HOURLY" : program.monitoringTier === "WEEKLY_DEEP" ? "WEEKLY" : "DAILY" },
      });
    }
    return this.prisma.securitySchedule.create({
      data: {
        workspaceId, name, kind: "EASM_DISCOVERY", expression,
        frequency: program.monitoringTier === "HOURLY_LIGHT" ? "HOURLY" : program.monitoringTier === "WEEKLY_DEEP" ? "WEEKLY" : "DAILY",
        timezone: "UTC", nextRunAt: new Date(), enabled: program.monitoringEnabled as boolean,
        createdBy: user.id, missedRunPolicy: "SKIP",
      },
    });
  }

  /**
   * Operator tick: run every due, monitoring-enabled program once.
   * Uses a system actor; discovery still passes every internal gate
   * (program status, policy, active-authorization) inside
   * runDiscovery — the tick grants nothing.
   */
  async tick(user: RequestUser, workspaceId: string) {
    requireEasmPermission(user, "RUN_EASM_DISCOVERY");
    const programs = (await this.prisma.easmProgram.findMany({
      where: { workspaceId, monitoringEnabled: true, status: "ACTIVE" },
    })) as Row[];
    const results: Array<{ programId: string; status: string; runId?: string; reason?: string }> = [];
    for (const program of programs) {
      const schedule = await this.prisma.securitySchedule.findFirst({
        where: { workspaceId, kind: "EASM_DISCOVERY", name: `EASM discovery: ${program.name as string}`, enabled: true },
      });
      if (schedule && new Date(schedule.nextRunAt as unknown as string).getTime() > Date.now()) {
        results.push({ programId: program.id as string, status: "NOT_DUE" });
        continue;
      }
      const systemUser: RequestUser = { id: "system:easm-scheduler", email: "easm-scheduler@system", organizationId: user.organizationId, role: "ADMIN" };
      try {
        const out = await this.discovery.runDiscovery(systemUser, workspaceId, program.id as string, {
          trigger: "SCHEDULED",
          limitSources: EasmMonitoringService.tierSources(program.monitoringTier as string),
        });
        if (schedule) {
          const intervalMs = program.monitoringTier === "HOURLY_LIGHT" ? 3600_000 : program.monitoringTier === "WEEKLY_DEEP" ? 7 * 86_400_000 : 86_400_000;
          await this.prisma.securitySchedule.update({
            where: { id: schedule.id as string },
            data: { lastRunAt: new Date(), nextRunAt: new Date(Date.now() + intervalMs), lastStatus: "COMPLETED" },
          });
        }
        results.push({ programId: program.id as string, status: "RAN", runId: (out.run as Row).id as string });
      } catch (e) {
        results.push({ programId: program.id as string, status: "BLOCKED", reason: e instanceof Error ? e.message : "unknown" });
      }
    }
    return { tickedAt: new Date().toISOString(), results };
  }
}
