import { Controller, ForbiddenException, Get, Inject, NotFoundException, Param, Patch, Body, Query } from "@nestjs/common";
import { z } from "zod";
import {
  CAPABILITIES, NUCLEI_TEMPLATE_CATALOG, NUCLEI_TEMPLATE_SNAPSHOT, RISK_LEVELS, TOOL_CATEGORIES, approvedReviewIdsForProfile, createApiAdapters, createCloudNativeAdapters, createCloudSecAdapters, createDirectoryAdapters, createNetworkAdapters, createReconAdapters, createVulnAdapters, createWebDiscoveryAdapters, type SecurityToolAdapter,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";

/** Prompt 8: interactive proxy scanner products (health is instance-driven).
 *  Prompt 9 adds mitmproxy to the same instance-driven family. */
const PROXY_TOOL_SLUGS: string[] = ["owasp-zap", "burp-suite-professional", "caido", "mitmproxy"];

/** Prompt 9: platform importers are code, not binaries — always HEALTHY. */
const IMPORTER_TOOL_SLUGS: string[] = ["postman", "insomnia"];

/** Prompt 14: provider inventory connectors have no binary — their
 *  health is whether the caller's organization has a registered cloud
 *  account for that provider (§9). */
const CLOUD_CONNECTOR_PROVIDERS: Record<string, string> = {
  "aws-inventory": "AWS", "azure-inventory": "AZURE", "gcp-inventory": "GCP",
};

/** Prompt 14: import connectors are fed by recorded exports in the
 *  worker artifact store; with no export source configured they are
 *  honestly NOT_CONFIGURED (§27/§29). */
const CLOUD_IMPORT_SLUGS: string[] = ["cloudmapper", "roadtools"];

const updateToolSchema = z.object({ enabled: z.boolean().optional() });

const listQuerySchema = z.object({
  category: z.enum(TOOL_CATEGORIES).optional(),
  riskLevel: z.enum(RISK_LEVELS).optional(),
  health: z.string().max(32).optional(),
  enabled: z.enum(["true", "false"]).optional(),
  capability: z.enum(CAPABILITIES).optional(),
  search: z.string().max(100).optional(),
});

/**
 * Tool management is metadata only. There is deliberately NO endpoint that
 * executes a tool or accepts a command — execution happens exclusively
 * through authorized assessment/scan workflows in the worker (later phases).
 */
@Controller("tools")
export class ToolsController {
  /** Recon adapters probed live for health (§39). Built once; the probe is
   *  a PATH lookup + `--version` on THIS host — the worker host probes again
   *  at execution time, and plan-time/execution-time health always wins. */
  private readonly reconAdapters: SecurityToolAdapter[] = [...createReconAdapters(), ...createWebDiscoveryAdapters(), ...createVulnAdapters(), ...createApiAdapters(), ...createNetworkAdapters(), ...createCloudNativeAdapters(), ...createCloudSecAdapters(), ...createDirectoryAdapters()];

  /** Brief cache for live adapter probes so repeated health reads by
   *  privileged callers do not spawn a host process per request. */
  private readonly probeCache = new Map<string, { at: number; result: { slug: string; healthStatus: string; installed: boolean; detail: string | undefined; source: string } }>();
  private static readonly PROBE_CACHE_TTL_MS = 30_000;

  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  /**
   * Catalog listing (Prompt 3 §42/§43). Filters are validated enums/strings;
   * responses contain metadata only — adapter rows expose capabilities,
   * targets, timeouts and credential REFERENCE names, never secret values,
   * and there is no execution field anywhere in this payload.
   */
  @Get()
  async list(@Query() query: Record<string, string> = {}) {
    const q = parseOrThrow(listQuerySchema, query);
    const where: Record<string, unknown> = {};
    if (q.category) where.category = q.category;
    if (q.riskLevel) where.riskLevel = q.riskLevel;
    if (q.health) where.healthStatus = q.health;
    if (q.enabled) where.enabled = q.enabled === "true";
    if (q.search) where.name = { contains: q.search, mode: "insensitive" };
    if (q.capability) where.adapters = { some: { capabilities: { array_contains: [q.capability] } } };
    return this.prisma.tool.findMany({ where, include: { adapters: true }, orderBy: { name: "asc" } });
  }

  @Get("categories")
  async categories() { return TOOL_CATEGORIES; }

  @Get("capabilities")
  async capabilities() {
    const adapters = await this.prisma.toolAdapter.findMany({ select: { capabilities: true } });
    const set = new Set<string>();
    for (const a of adapters) for (const c of (a.capabilities as string[]) ?? []) set.add(c);
    return [...set].sort();
  }

  /**
   * Nuclei template governance (Prompt 7 §4/§47): the admin UI reads the
   * governed catalog + snapshot + selection rules from here so what it
   * shows is exactly what the worker enforces. Owner/Admin only. There is
   * deliberately NO endpoint to upload templates or add template paths —
   * custom templates are an architecture note (§48), not an upload box.
   */
  @Get("template-policy")
  @Roles("OWNER", "ADMIN")
  templatePolicy() {
    return {
      snapshot: NUCLEI_TEMPLATE_SNAPSHOT,
      templates: NUCLEI_TEMPLATE_CATALOG.map((t) => ({
        id: t.id, name: t.name, classification: t.classification,
        vulnClass: t.vulnClass, severity: t.severity,
        ...(t.approvedForComprehensive ? { approvedForComprehensive: true } : {}),
      })),
      selectionRules: {
        automated: "SAFE templates, plus REVIEW_REQUIRED templates explicitly approved for the profile",
        neverAutomated: ["INTRUSIVE", "DISABLED"],
        approvedReviewByProfile: {
          WEB_BASELINE: approvedReviewIdsForProfile("WEB_BASELINE"),
          WEB_COMPREHENSIVE: approvedReviewIdsForProfile("WEB_COMPREHENSIVE"),
        },
        unknownTemplates: "REVIEW_REQUIRED — never SAFE by default, never auto-selected without approval",
        customTemplates: "Not supported for upload in this phase (§48): administrator-reviewed, version-controlled template collections only, admitted through the same classification policy.",
      },
    };
  }

  @Get(":id")
  async get(@Param("id") id: string) {
    const tool = await this.prisma.tool.findFirst({ where: { OR: [{ id }, { slug: id }] }, include: { adapters: true } });
    if (!tool) throw new NotFoundException("Tool not found");
    return tool;
  }

  @Get(":id/health")
  async health(@Param("id") id: string, @CurrentUser() user?: RequestUser) {
    const tool = await this.prisma.tool.findFirst({ where: { OR: [{ id }, { slug: id }] }, select: { slug: true, healthStatus: true, installed: true } });
    if (!tool) throw new NotFoundException("Tool not found");
    // Prompt 8 §53/§56/§66: proxy connectors have no binary to probe —
    // their health comes from the caller's registered scanner instances.
    // No instance in the caller's organization => NOT_CONFIGURED, an
    // honest state, never a fake HEALTHY.
    if (PROXY_TOOL_SLUGS.includes(tool.slug)) {
      const delegate = (this.prisma as unknown as {
        scannerInstance?: {
          findMany: (args: unknown) => Promise<Array<{ healthStatus: string; version: string | null; licenseState: string | null; lastHealthDetail: string | null }>>;
        };
      }).scannerInstance;
      const instances = delegate && user?.organizationId
        ? await delegate.findMany({ where: { organizationId: user.organizationId, enabled: true, tool: { slug: tool.slug } }, orderBy: { createdAt: "asc" } })
        : [];
      if (instances.length === 0) {
        return {
          slug: tool.slug, healthStatus: "NOT_CONFIGURED", installed: false, configuredInstances: 0,
          detail: "No scanner instance is registered for your organization — an administrator registers one under Settings → Scanner Instances (Prompt 8 §54)",
          source: "scanner instance registry",
        };
      }
      const first = instances[0]!;
      return {
        slug: tool.slug, healthStatus: first.healthStatus,
        installed: first.healthStatus === "HEALTHY" || first.healthStatus === "DEGRADED",
        configuredInstances: instances.length,
        version: first.version, licenseState: first.licenseState,
        detail: first.lastHealthDetail ?? "Health as of the last administrator health check",
        source: "scanner instance registry (administrator health checks; workers re-probe at execution time)",
      };
    }
    // Prompt 13 §34/§93: the Kubernetes connector has no binary — its
    // health is whether the caller's organization has a registered
    // cluster connection. Falco is a runtime sensor feed, configured
    // per deployment; neither is ever faked HEALTHY.
    if (tool.slug === "kubernetes-connector") {
      const delegate = (this.prisma as unknown as {
        kubernetesCluster?: { count: (args: unknown) => Promise<number> };
      }).kubernetesCluster;
      const clusters = delegate && user?.organizationId
        ? await delegate.count({ where: { workspace: { organizationId: user.organizationId } } })
        : 0;
      return clusters > 0
        ? { slug: tool.slug, healthStatus: "HEALTHY", installed: true, configuredInstances: clusters, detail: "Cluster connection(s) registered; inventory runs read-only from the worker (§34)", source: "kubernetes cluster registry" }
        : { slug: tool.slug, healthStatus: "NOT_CONFIGURED", installed: false, configuredInstances: 0, detail: "No Kubernetes cluster is registered for your organization — register one under Kubernetes (Prompt 13 §32)", source: "kubernetes cluster registry" };
    }
    if (tool.slug === "falco") {
      return {
        slug: tool.slug, healthStatus: "NOT_CONFIGURED", installed: false,
        detail: "Falco is a runtime sensor: events arrive through the trusted ingestion path (§59); no sensor feed is configured on this deployment",
        source: "runtime sensor configuration",
      };
    }
    // Prompt 14 §34/§89: Pacu is offensive cloud tooling — registered
    // DISABLED with NO adapter behind it. It is never probed, never
    // enabled by health, and no stage can select it.
    if (tool.slug === "pacu") {
      return {
        slug: tool.slug, healthStatus: "DISABLED", installed: false,
        detail: "Pacu (CLOUD_OFFENSIVE_TESTING, INTRUSIVE/HIGH) is disabled by policy: ZeroSweep performs read-only assessment only (§7/§34) — no adapter exists and it can never execute",
        source: "governed tool policy (Prompt 14 §34)",
      };
    }
    // Prompt 14 §9: cloud inventory connectors report per-account
    // health — HEALTHY only when the caller's organization has a
    // registered account for the provider.
    const cloudProvider = CLOUD_CONNECTOR_PROVIDERS[tool.slug];
    if (cloudProvider) {
      const delegate = (this.prisma as unknown as {
        cloudAccount?: { count: (args: unknown) => Promise<number> };
      }).cloudAccount;
      const accounts = delegate && user?.organizationId
        ? await delegate.count({ where: { provider: cloudProvider, workspace: { organizationId: user.organizationId } } })
        : 0;
      return accounts > 0
        ? { slug: tool.slug, healthStatus: "HEALTHY", installed: true, configuredInstances: accounts, detail: "Cloud account(s) registered; inventory runs read-only from the CLOUD_ANALYSIS worker (§7/§16)", source: "cloud account registry" }
        : { slug: tool.slug, healthStatus: "NOT_CONFIGURED", installed: false, configuredInstances: 0, detail: "No cloud account is registered for your organization — register one under Cloud Security (Prompt 14 §4)", source: "cloud account registry" };
    }
    if (CLOUD_IMPORT_SLUGS.includes(tool.slug)) {
      return {
        slug: tool.slug, healthStatus: "NOT_CONFIGURED", installed: false,
        detail: "Import connector: fed by recorded exports in the worker artifact store; no export source is configured on this deployment (§27/§29)",
        source: "import connector configuration",
      };
    }
    // Prompt 9: the Postman/Insomnia importers are platform code (no
    // binary, no instance) — health is HEALTHY by construction, exactly
    // like the jwt_tool inspection adapter reports through the probe
    // below.
    if (IMPORTER_TOOL_SLUGS.includes(tool.slug)) {
      return {
        slug: tool.slug, healthStatus: "HEALTHY", installed: true,
        detail: "Platform importer — specification/collection imports are parsed in-process under the §66/§74 guards",
        source: "platform importer registry",
      };
    }
    // Prompt 5 §39: for adapters implemented in code, privileged callers
    // get LIVE health — real version when the binary is present, honest
    // UNAVAILABLE when not. The live probe spawns a host process and its
    // detail carries host binary version/path, so it is gated to OWNER /
    // ADMIN / platform admins; every other authenticated caller gets
    // only the stored catalog health, with no host detail.
    const adapter = this.reconAdapters.find((a) => a.metadata.slug === tool.slug);
    if (adapter) {
      const privileged = user?.isPlatformAdmin === true || user?.role === "OWNER" || user?.role === "ADMIN";
      if (!privileged) {
        return {
          slug: tool.slug, healthStatus: tool.healthStatus, installed: tool.installed,
          source: "stored catalog health (live probe restricted to OWNER/ADMIN/platform administrators)",
        };
      }
      const cached = this.probeCache.get(tool.slug);
      if (cached && Date.now() - cached.at < ToolsController.PROBE_CACHE_TTL_MS) return cached.result;
      const live = await adapter.healthCheck();
      const result = {
        slug: tool.slug,
        healthStatus: live.status,
        installed: live.status === "HEALTHY",
        detail: live.detail,
        source: "live control-plane probe (worker hosts probe again at execution time)",
      };
      this.probeCache.set(tool.slug, { at: Date.now(), result });
      return result;
    }
    return tool;
  }

  @Patch(":id")
  async update(@Param("id") id: string, @Body() body: unknown, @CurrentUser() user?: RequestUser) {
    // The Tool row is GLOBAL (untenanted, shared by every tenant): the
    // enabled flag is deployment-level state, so only a platform
    // administrator may change it — tenant OWNER/ADMIN roles do not
    // suffice (same boundary as the platform-ops plane).
    if (user?.isPlatformAdmin !== true) {
      throw new ForbiddenException("changing global tool state requires a platform administrator; organization roles do not grant it");
    }
    const data = parseOrThrow(updateToolSchema, body);
    const tool = await this.prisma.tool.findFirst({ where: { OR: [{ id }, { slug: id }] } });
    if (!tool) throw new NotFoundException("Tool not found");
    return this.prisma.tool.update({ where: { id: tool.id }, data });
  }
}
