import { Controller, Get, Inject, Param, Query } from "@nestjs/common";
import { z } from "zod";
import {
  NSE_SCRIPT_CATALOG, NSE_POLICY_SNAPSHOT, createNetworkAdapters, type SecurityToolAdapter,
} from "@zerosweep/security-sdk";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { AuditService } from "../audit/audit.service";
import { NetworkService } from "./network.service";

const hostQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().max(200).optional(),
  network: z.string().max(64).optional(),
});

const captureQuerySchema = z.object({ scanId: z.string().max(64).optional() });

/** §86: the network tool surface — the 8 worker adapters plus Wireshark,
 *  which is a manual analyst tool (§46): present so operators see its
 *  role honestly (no adapter, no worker execution). */
const WIRESHARK_ENTRY = {
  slug: "wireshark", name: "Wireshark", manual: true,
  detail: "Manual/desktop analyst tool — authorized capture exports are imported and analyzed offline by tshark (§46)",
};

/**
 * Network inventory + capture endpoints (Prompt 10 §66–§73). Read-only:
 * there is NO endpoint here that starts a scan, runs a tool or accepts a
 * command — network scans start exclusively through the authorized
 * assessment/scan workflow. Raw packet-capture access is OWNER/ADMIN,
 * always audited (RAW_PCAP_ACCESSED), and returns artifact references +
 * integrity hashes — packet bytes live in worker object storage (§47).
 */
@Controller("network")
export class NetworkController {
  private readonly adapters: SecurityToolAdapter[] = createNetworkAdapters();

  constructor(
    private readonly network: NetworkService,
    private readonly audit: AuditService,
  ) {}

  @Get("networks")
  async networks(@CurrentUser() user: RequestUser) {
    return this.network.listNetworks(user);
  }

  @Get("hosts")
  async hosts(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const q = parseOrThrow(hostQuerySchema, query ?? {});
    return this.network.listHosts(user, { page: q.page ?? 1, pageSize: q.pageSize ?? 20, search: q.search, network: q.network });
  }

  @Get("hosts/:id")
  async host(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.network.getHost(user, id);
  }

  @Get("hosts/:id/services")
  async hostServices(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.network.listHostServices(user, id);
  }

  @Get("scans/:scanId/summary")
  async scanSummary(@CurrentUser() user: RequestUser, @Param("scanId") scanId: string) {
    return this.network.scanNetworkSummary(user, scanId);
  }

  @Get("scans/:scanId/hosts")
  async scanHosts(@CurrentUser() user: RequestUser, @Param("scanId") scanId: string) {
    return this.network.scanHosts(user, scanId);
  }

  @Get("packet-captures")
  async packetCaptures(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const q = parseOrThrow(captureQuerySchema, query ?? {});
    return this.network.listPacketCaptures(user, { scanId: q.scanId });
  }

  @Get("packet-captures/:id/raw")
  @Roles("OWNER", "ADMIN")
  async rawCapture(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const { workspace, capture } = await this.network.loadCaptureForRawAccess(user, id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "RAW_PCAP_ACCESSED", resourceType: "PacketCaptureArtifact", resourceId: capture.id as string,
      metadata: { format: capture.format as string, source: capture.source as string },
    });
    return {
      id: capture.id, format: capture.format, source: capture.source,
      storageKey: capture.storageKey, sha256: capture.sha256 ?? null,
      sizeBytes: capture.sizeBytes ?? null,
      access: "REFERENCE_ONLY",
      detail: "Raw capture bytes live in object storage; this audited reference is what an authorized analyst uses to retrieve them (§47). Every access is recorded.",
    };
  }

  /** §86: availability / version / capabilities / risk / required worker
   *  type for the network tools — probed live on this host exactly like
   *  the Tools pages, plus the NSE governance snapshot for Nmap. */
  @Get("tools")
  async tools() {
    const out = [];
    for (const adapter of this.adapters) {
      const live = await adapter.healthCheck();
      out.push({
        slug: adapter.metadata.slug, name: adapter.metadata.name,
        healthStatus: live.status, detail: live.detail ?? null,
        capabilities: adapter.metadata.capabilities,
        riskLevel: adapter.metadata.riskLevel,
        requiredWorkerType: adapter.metadata.requiredWorkerType ?? null,
        requiresApproval: adapter.metadata.requiresApproval,
        manual: false,
      });
    }
    return {
      tools: [...out, { ...WIRESHARK_ENTRY, healthStatus: "MANUAL", detail: WIRESHARK_ENTRY.detail, capabilities: ["PACKET_ANALYSIS"], riskLevel: "PASSIVE", requiredWorkerType: null, requiresApproval: false }],
      nseGovernance: {
        snapshot: NSE_POLICY_SNAPSHOT,
        scripts: NSE_SCRIPT_CATALOG.map((s) => ({ id: s.id, classification: s.classification, produces: s.produces })),
      },
    };
  }
}

/** §73 literal routes on the scans resource: per-scan network summary +
 *  host list, delegating to the same tenant-isolated service. */
@Controller("scans")
export class ScanNetworkController {
  constructor(private readonly network: NetworkService) {}

  @Get(":id/network-summary")
  async summary(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.network.scanNetworkSummary(user, id);
  }

  @Get(":id/hosts")
  async hosts(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.network.scanHosts(user, id);
  }
}
