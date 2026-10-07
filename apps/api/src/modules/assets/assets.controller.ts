import { Controller, Get, Param, Query } from "@nestjs/common";
import { z } from "zod";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { AssetsService } from "./assets.service";

const assetQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  scopeStatus: z.enum(["IN_SCOPE", "OUT_OF_SCOPE", "PENDING_REVIEW"]).optional(),
  technology: z.string().max(100).optional(),
  source: z.string().max(64).optional(),
  search: z.string().max(200).optional(),
});

const endpointQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  scopeStatus: z.enum(["IN_SCOPE", "OUT_OF_SCOPE"]).optional(),
  search: z.string().max(200).optional(),
  method: z.string().max(10).optional(),
  endpointType: z.enum(["PAGE", "DIRECTORY", "FILE", "API", "STATIC", "UNKNOWN"]).optional(),
  source: z.string().max(64).optional(),
});

/**
 * Asset + endpoint inventory (Prompt 5 §43–§45, §48). Read-only views over
 * what authorized scans discovered — there is deliberately no write or
 * execute surface here.
 */
@Controller("assets")
export class AssetsController {
  constructor(private readonly assets: AssetsService) {}

  @Get()
  async list(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const q = parseOrThrow(assetQuerySchema, query ?? {});
    return this.assets.listAssets(user, {
      page: q.page ?? 1, pageSize: q.pageSize ?? 20,
      scopeStatus: q.scopeStatus, technology: q.technology, source: q.source, search: q.search,
    });
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.getAsset(user, id);
  }

  @Get(":id/services")
  async services(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.listAssetServices(user, id);
  }

  @Get(":id/endpoints")
  async endpoints(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.listAssetEndpoints(user, id);
  }

  /** The asset's discovered web surface (Prompt 6 §55). */
  @Get(":id/web-surface")
  async webSurface(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.getAssetWebSurface(user, id);
  }
}

@Controller("endpoints")
export class EndpointsController {
  constructor(private readonly assets: AssetsService) {}

  @Get()
  async list(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const q = parseOrThrow(endpointQuerySchema, query ?? {});
    return this.assets.listEndpoints(user, {
      page: q.page ?? 1, pageSize: q.pageSize ?? 20,
      scopeStatus: q.scopeStatus, search: q.search,
      method: q.method, endpointType: q.endpointType, source: q.source,
    });
  }

  /** Endpoint detail with parameters + forms (Prompt 6 §55). */
  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.getEndpoint(user, id);
  }

  /** Discovered parameters of one endpoint — names only (§55). */
  @Get(":id/parameters")
  async parameters(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.listEndpointParameters(user, id);
  }
}
