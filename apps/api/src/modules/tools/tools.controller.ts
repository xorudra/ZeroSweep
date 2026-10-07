import { Controller, Get, Inject, NotFoundException, Param, Patch, Body } from "@nestjs/common";
import { z } from "zod";
import { TOOL_CATEGORIES } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { Roles } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";

const updateToolSchema = z.object({ enabled: z.boolean().optional() });

/**
 * Tool management is metadata only. There is deliberately NO endpoint that
 * executes a tool or accepts a command — execution happens exclusively
 * through authorized assessment/scan workflows in the worker (later phases).
 */
@Controller("tools")
export class ToolsController {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  @Get()
  async list() {
    return this.prisma.tool.findMany({ include: { adapters: true }, orderBy: { name: "asc" } });
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
