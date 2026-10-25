import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";
import { z } from "zod";
import { registerAdDomainSchema, startAdScanSchema } from "@zerosweep/validation";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { ActiveDirectoryService } from "./active-directory.service";

const domainQuerySchema = z.object({
  domainId: z.string().min(1).optional(),
});

const usersQuerySchema = z.object({
  domainId: z.string().min(1).optional(),
  privileged: z.enum(["true", "false"]).optional(),
  search: z.string().min(1).max(200).optional(),
});

const driftQuerySchema = z.object({
  domainId: z.string().min(1).optional(),
  kind: z.string().min(1).max(64).optional(),
});

const scanBodySchema = startAdScanSchema.extend({
  // §100/§112: a scan request may name tools; naming an OFFENSIVE
  // tool is refused and audited (AD_OFFENSIVE_ACTION_BLOCKED) — the
  // field exists so the refusal is explicit, never silent.
  requestedTools: z.array(z.string().min(1).max(128)).max(32).optional(),
});

/**
 * Active Directory security endpoints (Prompt 15 §100). Registration,
 * validation and scan starts are the only writes; everything else is
 * a tenant-scoped read. There is NO endpoint that modifies a
 * directory object, executes an attack path, exploits AD CS, browses
 * share contents, accepts a credential value, or runs a tool
 * command — assessment is defensive and read-only (§83/§120).
 */
@Controller()
export class ActiveDirectoryController {
  constructor(private readonly ad: ActiveDirectoryService) {}

  // Forests + domains (§100)
  @Get("ad/forests")
  async listForests(@CurrentUser() user: RequestUser) {
    return this.ad.listForests(user);
  }

  @Get("ad/domains")
  async listDomains(@CurrentUser() user: RequestUser) {
    return this.ad.listDomains(user);
  }

  @Post("ad/domains")
  async registerDomain(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(registerAdDomainSchema, body ?? {});
    return this.ad.registerDomain(user, input);
  }

  @Get("ad/domains/:id")
  async getDomain(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.ad.getDomain(user, id);
  }

  @Post("ad/domains/:id/validate")
  async validateDomain(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.ad.validateDomain(user, id);
  }

  @Post("ad/domains/:id/scan")
  async scanDomain(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(scanBodySchema, body ?? {});
    if (input.requestedTools && input.requestedTools.length > 0) {
      await this.ad.assertNoOffensiveTools(user, id, input.requestedTools);
    }
    return this.ad.startDomainScan(user, id, { profile: input.profile });
  }

  // Identities (§100)
  @Get("ad/users")
  async listUsers(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(usersQuerySchema, query ?? {});
    return this.ad.listUsers(user, {
      ...(input.domainId ? { domainId: input.domainId } : {}),
      ...(input.privileged !== undefined ? { privileged: input.privileged === "true" } : {}),
      ...(input.search ? { search: input.search } : {}),
    });
  }

  @Get("ad/users/:id")
  async getUser(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.ad.getUser(user, id);
  }

  @Get("ad/groups")
  async listGroups(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(domainQuerySchema, query ?? {});
    return this.ad.listGroups(user, input);
  }

  @Get("ad/groups/:id")
  async getGroup(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.ad.getGroup(user, id);
  }

  @Get("ad/computers")
  async listComputers(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(domainQuerySchema, query ?? {});
    return this.ad.listComputers(user, input);
  }

  @Get("ad/computers/:id")
  async getComputer(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.ad.getComputer(user, id);
  }

  @Get("ad/trusts")
  async listTrusts(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(domainQuerySchema, query ?? {});
    return this.ad.listTrusts(user, input);
  }

  // Graph + attack paths (§100)
  @Get("ad/graph")
  async getGraph(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(domainQuerySchema, query ?? {});
    return this.ad.getGraph(user, input);
  }

  @Get("ad/graph/raw")
  async getRawGraph(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(domainQuerySchema, query ?? {});
    return this.ad.getRawGraph(user, input);
  }

  @Get("ad/attack-paths")
  async listAttackPaths(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(domainQuerySchema, query ?? {});
    return this.ad.listAttackPaths(user, input);
  }

  // AD CS + SMB + drift + compliance (§100)
  @Get("ad/adcs")
  async listAdcs(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(domainQuerySchema, query ?? {});
    return this.ad.listAdcs(user, input);
  }

  @Get("ad/smb")
  async listSmb(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(domainQuerySchema, query ?? {});
    return this.ad.listSmb(user, input);
  }

  @Get("ad/drift")
  async listDrift(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(driftQuerySchema, query ?? {});
    return this.ad.listDrift(user, input);
  }

  @Get("ad/compliance")
  async listCompliance(@CurrentUser() user: RequestUser) {
    return this.ad.listCompliance(user);
  }
}
