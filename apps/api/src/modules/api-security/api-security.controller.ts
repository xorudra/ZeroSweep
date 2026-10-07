import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";
import { z } from "zod";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { ApiSecurityService } from "./api-security.service";

const importSchema = z.object({
  targetId: z.string().min(1).max(64),
  content: z.string().min(1),
  location: z.string().max(2048).optional(),
});
const postmanImportSchema = importSchema.extend({ environment: z.string().optional() });
const graphqlImportSchema = z.object({
  targetId: z.string().min(1).max(64),
  endpointUrl: z.string().min(1).max(2048),
  content: z.string().min(1),
});
const jwtInspectSchema = z.object({
  token: z.string().min(1).max(16384),
  host: z.string().max(255).optional(),
  endpoint: z.string().max(2048).optional(),
});
const listQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  method: z.string().max(10).optional(),
  search: z.string().max(200).optional(),
});
const testCaseSchema = z.object({
  endpointId: z.string().max(64).optional(),
  objectIdentifier: z.string().max(200).optional(),
  identityAContextId: z.string().max(64).optional(),
  identityBContextId: z.string().max(64).optional(),
  expectedAccess: z.string().max(200).optional(),
});
const testDataSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  data: z.record(z.unknown()).optional(),
});
const authContextSchema = z.object({
  role: z.enum(["ANONYMOUS", "USER_A", "USER_B", "ADMIN_TEST"]),
  credentialReference: z.string().max(128).optional(),
  sessionProfileId: z.string().max(64).optional(),
  apiServiceId: z.string().max(64).optional(),
});

const WRITE_ROLES = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"] as const;

/**
 * API security surface (Prompt 9 §50–§60). Imports are guarded writes;
 * everything else is workspace-scoped inventory. There is deliberately
 * NO execute/run endpoint here — API checks run only inside approved
 * scans through the worker (§4).
 */
@Controller("api-security")
export class ApiSecurityController {
  constructor(private readonly apiSecurity: ApiSecurityService) {}

  @Post("imports/openapi")
  @Roles(...WRITE_ROLES)
  async importOpenApi(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.apiSecurity.importOpenApi(user, parseOrThrow(importSchema, body ?? {}));
  }

  @Post("imports/postman")
  @Roles(...WRITE_ROLES)
  async importPostman(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.apiSecurity.importPostman(user, parseOrThrow(postmanImportSchema, body ?? {}));
  }

  @Post("imports/insomnia")
  @Roles(...WRITE_ROLES)
  async importInsomnia(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.apiSecurity.importInsomnia(user, parseOrThrow(importSchema, body ?? {}));
  }

  @Post("imports/graphql")
  @Roles(...WRITE_ROLES)
  async importGraphql(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.apiSecurity.importGraphql(user, parseOrThrow(graphqlImportSchema, body ?? {}));
  }

  @Post("jwt/inspect")
  @Roles(...WRITE_ROLES)
  async inspectJwt(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.apiSecurity.inspectJwt(user, parseOrThrow(jwtInspectSchema, body ?? {}));
  }

  @Get("summary")
  async summary(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.summary(user);
  }

  @Get("services")
  async services(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.listServices(user);
  }

  @Get("services/:id")
  async service(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.apiSecurity.getService(user, id);
  }

  @Get("endpoints")
  async endpoints(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const q = parseOrThrow(listQuerySchema, query ?? {});
    return this.apiSecurity.listEndpoints(user, {
      page: q.page ?? 1, pageSize: q.pageSize ?? 20, method: q.method, search: q.search,
    });
  }

  @Get("endpoints/:id")
  async endpoint(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.apiSecurity.getEndpoint(user, id);
  }

  @Get("graphql")
  async graphql(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.listGraphql(user);
  }

  @Get("websockets")
  async websockets(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.listWebSockets(user);
  }

  @Get("jwt-profiles")
  async jwtProfiles(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.listJwtProfiles(user);
  }

  @Get("specifications")
  async specifications(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.listSpecifications(user);
  }

  @Get("authorization-test-cases")
  async testCases(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.listAuthorizationTestCases(user);
  }

  @Post("authorization-test-cases")
  @Roles(...WRITE_ROLES)
  async createTestCase(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.apiSecurity.createAuthorizationTestCase(user, parseOrThrow(testCaseSchema, body ?? {}));
  }

  @Get("test-data-profiles")
  async testDataProfiles(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.listTestDataProfiles(user);
  }

  @Post("test-data-profiles")
  @Roles(...WRITE_ROLES)
  async createTestDataProfile(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.apiSecurity.createTestDataProfile(user, parseOrThrow(testDataSchema, body ?? {}));
  }

  @Get("api-auth-contexts")
  async authContexts(@CurrentUser() user: RequestUser) {
    return this.apiSecurity.listApiAuthContexts(user);
  }

  @Post("api-auth-contexts")
  @Roles(...WRITE_ROLES)
  async createAuthContext(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.apiSecurity.createApiAuthContext(user, parseOrThrow(authContextSchema, body ?? {}));
  }
}
