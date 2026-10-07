import { Controller, Get, Inject, NotFoundException, Param, Patch, Body, Query } from "@nestjs/common";
import { z } from "zod";
import {
  CAPABILITIES, RISK_LEVELS, TOOL_CATEGORIES, createReconAdapters, createWebDiscoveryAdapters, type SecurityToolAdapter,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { Roles } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";

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
  private readonly reconAdapters: SecurityToolAdapter[] = [...createReconAdapters(), ...createWebDiscoveryAdapters()];

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

  @Get(":id")
  async get(@Param("id") id: string) {
    const tool = await this.prisma.tool.findFirst({ where: { OR: [{ id }, { slug: id }] }, include: { adapters: true } });
    if (!tool) throw new NotFoundException("Tool not found");
    return tool;
  }

  @Get(":id/health")
  async health(@Param("id") id: string) {
    const tool = await this.prisma.tool.findFirst({ where: { OR: [{ id }, { slug: id }] }, select: { slug: true, healthStatus: true, installed: true } });
    if (!tool) throw new NotFoundException("Tool not found");
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
