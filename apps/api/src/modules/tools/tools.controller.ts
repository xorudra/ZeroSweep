import { Controller, Get, Inject, NotFoundException, Param, Patch, Body, Query } from "@nestjs/common";
import { z } from "zod";
import {
  CAPABILITIES, NUCLEI_TEMPLATE_CATALOG, NUCLEI_TEMPLATE_SNAPSHOT, RISK_LEVELS, TOOL_CATEGORIES, approvedReviewIdsForProfile, createReconAdapters, createVulnAdapters, createWebDiscoveryAdapters, type SecurityToolAdapter,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";

/** Prompt 8: interactive proxy scanner products (health is instance-driven). */
const PROXY_TOOL_SLUGS: string[] = ["owasp-zap", "burp-suite-professional", "caido"];

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
  private readonly reconAdapters: SecurityToolAdapter[] = [...createReconAdapters(), ...createWebDiscoveryAdapters(), ...createVulnAdapters()];

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
    // Prompt 5 §39: for adapters implemented in code, report LIVE health —
    // real version when the binary is present, honest UNAVAILABLE when not.
    const adapter = this.reconAdapters.find((a) => a.metadata.slug === tool.slug);
    if (adapter) {
      const live = await adapter.healthCheck();
      return {
        slug: tool.slug,
        healthStatus: live.status,
        installed: live.status === "HEALTHY",
        detail: live.detail,
        source: "live control-plane probe (worker hosts probe again at execution time)",
      };
    }
    return tool;
  }

  @Patch(":id")
  @Roles("OWNER", "ADMIN")
  async update(@Param("id") id: string, @Body() body: unknown) {
    const data = parseOrThrow(updateToolSchema, body);
    const tool = await this.prisma.tool.findFirst({ where: { OR: [{ id }, { slug: id }] } });
    if (!tool) throw new NotFoundException("Tool not found");
    return this.prisma.tool.update({ where: { id: tool.id }, data });
  }
}
