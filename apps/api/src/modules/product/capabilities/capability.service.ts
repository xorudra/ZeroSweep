import { Inject, Injectable } from "@nestjs/common";
import {
  PRODUCT_FEATURE_REGISTRY, resolveCapability, resolveCommercialToolStatus,
  COMMERCIAL_TOOLS, type CapabilityResolution, type FeatureKey,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { EntitlementService } from "../entitlements/entitlement.service";
import { PlatformControlService } from "../../platform-ops/platform-control.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Feature → the worker capability that must be online (§120). */
const WORKER_CAPABILITY: Partial<Record<FeatureKey, string>> = {
  WEB_VAPT: "WEB", API_VAPT: "WEB", NETWORK_VAPT: "NETWORK", ASSET_DISCOVERY: "WEB",
  MOBILE_VAPT: "MOBILE", BINARY_ANALYSIS: "BINARY", SAST: "CODE", SCA: "CODE",
  CONTAINER_SECURITY: "CONTAINER", KUBERNETES_SECURITY: "CONTAINER",
};

/**
 * EffectiveCapabilityService (Prompt 40 §120). Combines entitlement ×
 * deployment capability × tool availability × worker availability ×
 * authorization × RBAC into one truthful state per feature (§121).
 * An entitled feature with no worker reports WORKER_UNAVAILABLE
 * (ENTITLED_BUT_UNAVAILABLE, §119/§226) — never "operational" (§277).
 */
@Injectable()
export class EffectiveCapabilityService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly entitlements: EntitlementService,
    private readonly platformControl: PlatformControlService,
  ) {}

  private async workerOnline(capability: string | undefined): Promise<boolean | null> {
    if (!capability) return null;
    const workers = await (this.prisma as any).workerNode.findMany({ where: { status: "ONLINE" } }).catch(() => []);
    if (!workers || workers.length === 0) return false;
    return workers.some((w: any) => {
      const caps = (w.capabilities ?? []) as string[];
      return caps.length === 0 || caps.some((c) => c.toUpperCase().includes(capability));
    });
  }

  async resolveForOrganization(organizationId: string, role: string): Promise<CapabilityResolution[]> {
    const { entitlements, enforcementActive } = await this.entitlements.getEffectiveEntitlements(organizationId);
    const byKey = new Map(entitlements.map((e) => [e.featureKey, e]));
    const control = await this.platformControl.getState().catch(() => null);
    const killSwitches = (control?.killSwitches ?? {}) as Record<string, { enabled: boolean }>;
    const anyKill = Object.values(killSwitches).some((k) => k?.enabled);

    const out: CapabilityResolution[] = [];
    for (const def of PRODUCT_FEATURE_REGISTRY) {
      const grant = byKey.get(def.key);
      const entitled = !enforcementActive || Boolean(grant?.enabled);
      const authorized = !["VIEWER", "CLIENT_VIEWER", "CLIENT_REMEDIATOR"].includes(role) || ["REPORTING", "CLIENT_PORTAL"].includes(def.key);
      const workerAvailable = await this.workerOnline(WORKER_CAPABILITY[def.key]);
      out.push(resolveCapability(def.key, {
        entitled,
        deployed: true,
        toolAvailable: null,
        workerAvailable,
        authorized,
        quotaAvailable: true,
        temporarilyDisabled: anyKill,
      }));
    }
    return out;
  }

  /** §122/§123: truthful commercial-tool status from registry facts. */
  async commercialToolStatuses(): Promise<Array<{ slug: string; name: string; status: string; termsNote: string }>> {
    const tools = await (this.prisma as any).tool.findMany({ where: { licenseType: "COMMERCIAL" } }).catch(() => []);
    return COMMERCIAL_TOOLS.map((ct) => {
      const row = (tools as any[]).find((t) => t.slug === ct.slug || t.name === ct.name);
      const customerConfigured = Boolean(row?.enabled && row?.installed);
      return {
        slug: ct.slug,
        name: ct.name,
        termsNote: ct.termsNote,
        status: resolveCommercialToolStatus({
          customerConfigured,
          connectorReachable: row ? row.healthStatus === "HEALTHY" : null,
          lastError: row?.healthStatus === "ERROR" ? "connector error" : null,
        }),
      };
    });
  }
}
