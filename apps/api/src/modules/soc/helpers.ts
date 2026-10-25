import { DEFAULT_SOC_SLA_MINUTES, type AlertPriority } from "@zerosweep/security-sdk";
import type { PrismaClientLike } from "../../prisma/prisma.module";

export type Row = Record<string, unknown>;

export type SlaTargets = Record<AlertPriority, { triage: number; acknowledge: number; containment: number; recovery: number }>;

/** §90: workspace SLA targets = shipped defaults overridden by the
 *  workspace SocSlaConfig row when present. */
export async function loadSlaTargets(prisma: PrismaClientLike, workspaceId: string): Promise<SlaTargets> {
  const targets = structuredClone(DEFAULT_SOC_SLA_MINUTES) as SlaTargets;
  const config = await prisma.socSlaConfig.findFirst({ where: { workspaceId } }).catch(() => null);
  if (config?.targets && typeof config.targets === "object") {
    for (const [priority, values] of Object.entries(config.targets as Record<string, unknown>)) {
      if (priority in targets && values && typeof values === "object") {
        Object.assign(targets[priority as AlertPriority], values as Record<string, number>);
      }
    }
  }
  return targets;
}

export const OPEN_ALERT_STATUSES = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED"];
