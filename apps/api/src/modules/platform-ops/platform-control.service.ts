import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import {
  KILL_SWITCHES, evaluateWork,
  type KillSwitch, type PlatformControlState, type WorkClass, type WorkDecision,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { AuditService } from "../audit/audit.service";
import { requirePlatformPermission } from "./permissions";

/**
 * Platform control plane (Prompt 38 §158/§159/§202): maintenance mode
 * and per-work-class kill switches, persisted as one global row and
 * audited on every change. Dangerous changes require an explicit
 * `confirm: true` in the request AND the MANAGE_MAINTENANCE permission.
 * Enforcement points call assertWorkAllowed — reads, health and the
 * admin plane itself are never blocked (operators must be able to see
 * and fix the platform while it is switched off).
 */
@Injectable()
export class PlatformControlService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async getState(): Promise<PlatformControlState> {
    const row = await this.prisma.platformControl.findUnique({ where: { key: "platform" } });
    if (!row) return { maintenanceMode: false, killSwitches: {} };
    return {
      maintenanceMode: row.maintenanceMode,
      maintenanceMessage: row.maintenanceMessage ?? undefined,
      killSwitches: (row.killSwitches ?? {}) as PlatformControlState["killSwitches"],
    };
  }

  private async upsert(state: PlatformControlState, userId: string) {
    await this.prisma.platformControl.upsert({
      where: { key: "platform" },
      create: {
        key: "platform",
        maintenanceMode: state.maintenanceMode,
        maintenanceMessage: state.maintenanceMessage ?? null,
        killSwitches: state.killSwitches as never,
        updatedById: userId,
      },
      update: {
        maintenanceMode: state.maintenanceMode,
        maintenanceMessage: state.maintenanceMessage ?? null,
        killSwitches: state.killSwitches as never,
        updatedById: userId,
      },
    });
  }

  async setMaintenance(
    user: RequestUser,
    input: { enabled: boolean; message?: string; confirm?: boolean },
  ): Promise<PlatformControlState> {
    requirePlatformPermission(user, "MANAGE_MAINTENANCE");
    if (input.confirm !== true) {
      throw new BadRequestException("maintenance mode changes require explicit confirmation (§202)");
    }
    const state = await this.getState();
    state.maintenanceMode = input.enabled;
    state.maintenanceMessage = input.enabled ? input.message : undefined;
    await this.upsert(state, user.id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: input.enabled ? "PLATFORM_MAINTENANCE_ENABLED" : "PLATFORM_MAINTENANCE_DISABLED",
      resourceType: "PlatformControl", resourceId: "platform",
      metadata: input.enabled && input.message ? { message: input.message } : {},
    });
    return state;
  }

  async setKillSwitch(
    user: RequestUser,
    input: { switch: string; enabled: boolean; reason?: string; confirm?: boolean },
  ): Promise<PlatformControlState> {
    requirePlatformPermission(user, "MANAGE_MAINTENANCE");
    if (!(KILL_SWITCHES as readonly string[]).includes(input.switch)) {
      throw new BadRequestException(`unknown kill switch ${input.switch} — closed set: ${KILL_SWITCHES.join(", ")}`);
    }
    if (input.confirm !== true) {
      throw new BadRequestException("kill switch changes require explicit confirmation (§202)");
    }
    const state = await this.getState();
    const name = input.switch as KillSwitch;
    state.killSwitches[name] = input.enabled
      ? { enabled: true, reason: input.reason, setById: user.id, setAt: new Date().toISOString() }
      : { enabled: false };
    await this.upsert(state, user.id);
    // Enabling the scan-starts switch uses the §204 SCAN_KILL_SWITCH_*
    // actions; other switches record the platform maintenance actions
    // with the switch name in metadata.
    const action = name === "SCAN_STARTS"
      ? (input.enabled ? "SCAN_KILL_SWITCH_ENABLED" : "SCAN_KILL_SWITCH_DISABLED")
      : (input.enabled ? "PLATFORM_MAINTENANCE_ENABLED" : "PLATFORM_MAINTENANCE_DISABLED");
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action, resourceType: "PlatformControl", resourceId: "platform",
      metadata: { switch: name, ...(input.reason ? { reason: input.reason } : {}) },
    });
    return state;
  }

  /** Enforcement helper (§158): used by scan start today; AI/report/
   *  integration gates call the same function. Never throws for READ /
   *  ADMIN work classes. */
  async checkWork(work: WorkClass): Promise<WorkDecision> {
    return evaluateWork(await this.getState(), work);
  }
}
