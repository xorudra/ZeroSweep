import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  ApiOperationPolicyEngine, GraphqlSchemaImporter, InsomniaImporter, JwtToolAdapter,
  OpenApiImporter, PostmanCollectionImporter, ScopeMatcher, SpecImportError,
  isSecretLikeKey, parsePostmanEnvironment,
  type ApiImportResult,
} from "@zerosweep/security-sdk";
import { scopeRulesSchema, type ScopeRules } from "@zerosweep/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { assertTargetInOrg, resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";

/**
 * API security API (Prompt 9 §50–§60, §67): guarded specification
 * imports, API/GraphQL/WebSocket/JWT inventory views, JWT inspection,
 * authorization test-case records, test-data profiles and API auth
 * contexts. Everything is workspace-scoped through the caller's
 * organization.
 *
 * Safety invariants:
 *  - Imports are HOSTILE input: the SDK importers enforce size/format/
 *    nesting limits; external references are never fetched (§66/§74).
 *  - An import yields INVENTORY only — never findings (§7).
 *  - Secrets are never accepted or stored: Postman/Insomnia secret
 *    values are dropped by the importers (names become references),
 *    auth contexts store credential REFERENCE NAMES only, and the JWT
 *    inspection endpoint returns fingerprint + redacted claims — the
 *    raw token is never persisted, logged or audited (§22–§25).
 *  - Blocked operations (state-changing/destructive under the §17
 *    policy) are counted and reported, never executed.
 */

const MAX_IMPORT_BYTES = 10 * 1024 * 1024; // §66, same cap as Phase 8 imports
const REFERENCE_NAME = /^[A-Z][A-Z0-9_]{2,127}$/;
const API_VULN_CLASSES = [
  "JWT_ALGORITHM_CONFIGURATION", "JWT_MISSING_EXPIRY", "JWT_EXCESSIVE_LIFETIME",
  "JWT_SENSITIVE_CLAIMS", "JWT_ISSUER_AUDIENCE_MISMATCH", "EXPOSED_API_DOCUMENTATION",
  "EXPOSED_DEBUG_ENDPOINT", "API_RESPONSE_CONFORMANCE", "API_SERVER_ERROR",
];

function hostOf(value: string): string {
  try { if (value.includes("://")) return new URL(value).hostname.toLowerCase(); } catch { /* fall through */ }
  return value.split("/")[0]!.split(":")[0]!.toLowerCase();
}

function pathTemplateOf(url: string): string {
  // Deliberately NOT new URL().pathname: the URL parser percent-encodes
  // `{`/`}`, which would corrupt path templates like /users/{id}.
  const withoutOrigin = url.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]+/i, "");
  const path = withoutOrigin.split(/[?#]/)[0] ?? "";
  return path.startsWith("/") ? path : `/${path}`;
}

export interface ImportSummary {
  specificationId: string;
  kind: string;
  services: number;
  endpoints: number;
  operations: number;
  blockedOperations: number;
  schemas: number;
  warnings: string[];
  /** Secret-named variables found in an imported environment — NAMES
   *  only; their values were dropped by the importer (§11). */
  secretReferences: string[];
}

@Injectable()
export class ApiSecurityService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  // ------------------------------ imports ------------------------------

  async importOpenApi(user: RequestUser, input: { targetId: string; content: string; location?: string }) {
    this.assertImportSize(input.content);
    let result: ApiImportResult;
    try {
      result = new OpenApiImporter().parse(input.content, {
        ...(input.location ? { baseUrl: input.location } : {}),
        source: "openapi-importer",
      });
    } catch (err) {
      throw new BadRequestException(err instanceof SpecImportError ? err.message : "OpenAPI document could not be parsed safely");
    }
    return this.persistImport(user, input.targetId, result, input.location);
  }

  async importPostman(user: RequestUser, input: { targetId: string; content: string; environment?: string; location?: string }) {
    this.assertImportSize(input.content);
    let result: ApiImportResult;
    try {
      result = new PostmanCollectionImporter().parse(input.content, {
        ...(input.location ? { baseUrl: input.location } : {}),
        source: "postman-importer",
      });
    } catch (err) {
      throw new BadRequestException(err instanceof SpecImportError ? err.message : "Postman collection could not be parsed safely");
    }
    const summary = await this.persistImport(user, input.targetId, result, input.location);
    if (input.environment) {
      // Environment secrets: only their NAMES survive, as references.
      const env = parsePostmanEnvironment(input.environment);
      summary.secretReferences = env.variables.filter((v) => v.secret).map((v) => v.key);
    }
    return summary;
  }

  async importInsomnia(user: RequestUser, input: { targetId: string; content: string; location?: string }) {
    this.assertImportSize(input.content);
    let result: ApiImportResult;
    try {
      result = new InsomniaImporter().parse(input.content, {
        ...(input.location ? { baseUrl: input.location } : {}),
        source: "insomnia-importer",
      });
    } catch (err) {
      throw new BadRequestException(err instanceof SpecImportError ? err.message : "Insomnia export could not be parsed safely");
    }
    return this.persistImport(user, input.targetId, result, input.location);
  }

  async importGraphql(user: RequestUser, input: { targetId: string; endpointUrl: string; content: string }) {
    this.assertImportSize(input.content);
    let result: ApiImportResult;
    try {
      result = new GraphqlSchemaImporter().parse(input.content, { endpointUrl: input.endpointUrl, source: "graphql-importer" });
    } catch (err) {
      throw new BadRequestException(err instanceof SpecImportError ? err.message : "GraphQL schema could not be parsed safely");
    }
    const summary = await this.persistImport(user, input.targetId, result, input.endpointUrl);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      workspaceId: summary.workspaceId, action: "GRAPHQL_SCHEMA_IMPORTED",
      resourceType: "ApiSpecification", resourceId: summary.specificationId,
      metadata: { operations: summary.operations, endpointUrl: input.endpointUrl },
    });
    return summary;
  }

  private assertImportSize(content: string) {
    if (typeof content !== "string" || content.length === 0) throw new BadRequestException("Import content is required");
    if (Buffer.byteLength(content, "utf8") > MAX_IMPORT_BYTES) throw new BadRequestException("Import exceeds the 10 MiB limit");
  }

  /** Shared persistence for every importer (§37 graph): specification +
   *  schemas + services + endpoints (template URLs intact) + audit.
   *  Raw content is NOT retained in Postgres — only its checksum and an
   *  object-storage reference, matching the Phase 8 import pattern. */
  private async persistImport(
    user: RequestUser, targetId: string, result: ApiImportResult, location?: string,
  ): Promise<ImportSummary & { workspaceId: string }> {
    const workspace = await resolveWorkspace(this.prisma, user);
    const target = await assertTargetInOrg(this.prisma, user, targetId);
    const matcher = await this.scopeMatcherFor(targetId, target.value as string);
    const checksum = result.specification.checksum;
    const targetHost = hostOf(target.value as string);
    const primaryAsset = await this.resolveAsset(workspace.id, targetId, targetHost);

    const specification = await this.prisma.apiSpecification.create({
      data: {
        workspaceId: workspace.id, targetId, assetId: primaryAsset.id,
        kind: result.specification.kind, version: result.specification.version,
        source: result.specification.source,
        location: location ?? result.specification.location,
        checksum, artifactRef: `api-specs/${workspace.id}/${checksum}`,
        operationCount: result.specification.operationCount, parsedStatus: "PARSED",
      },
    });

    // Schemas (§9/§36): structure only — property name → type summary,
    // never example values. Deduped per workspace by name+type.
    let schemaCount = 0;
    for (const schema of result.schemas) {
      const existing = await this.prisma.apiSchema.findFirst({
        where: { workspaceId: workspace.id, name: schema.name, schemaType: schema.schemaType },
      });
      if (existing) continue;
      await this.prisma.apiSchema.create({
        data: {
          workspaceId: workspace.id, name: schema.name, schemaType: schema.schemaType,
          requiredFields: schema.requiredFields ?? [], properties: (schema.properties ?? {}) as never,
          source: schema.source, artifactRef: `api-specs/${workspace.id}/${checksum}`,
        },
      });
      schemaCount++;
    }

    // Services (§37): upserted per asset+baseUrl with scope verdicts.
    for (const svc of result.apiServices) {
      const asset = await this.resolveAsset(workspace.id, targetId, svc.host);
      const scopeStatus = matcher.isUrlAllowed(svc.baseUrl) ? "IN_SCOPE" : "OUT_OF_SCOPE";
      await this.prisma.apiService.upsert({
        where: { assetId_baseUrl: { assetId: asset.id, baseUrl: svc.baseUrl } },
        create: {
          workspaceId: workspace.id, assetId: asset.id, baseUrl: svc.baseUrl, host: svc.host,
          apiType: svc.apiType, version: svc.version ?? result.specification.version,
          authenticationType: svc.authenticationType, specificationId: specification.id,
          source: svc.source, scopeStatus,
        },
        update: {
          apiType: svc.apiType, authenticationType: svc.authenticationType,
          specificationId: specification.id, source: svc.source, scopeStatus, lastSeen: new Date(),
        },
      });
    }

    // GraphQL services (§37): upserted per workspace+endpoint.
    for (const g of result.graphqlServices) {
      const asset = await this.resolveAsset(workspace.id, targetId, g.host);
      await this.prisma.graphqlService.upsert({
        where: { workspaceId_endpointUrl: { workspaceId: workspace.id, endpointUrl: g.endpointUrl } },
        create: {
          workspaceId: workspace.id, assetId: asset.id, endpointUrl: g.endpointUrl,
          schemaAvailable: g.schemaAvailable, queries: g.queries, mutations: g.mutations,
          subscriptions: g.subscriptions, types: g.types,
          authenticationRequired: g.authenticationRequired, source: g.source,
          scopeStatus: matcher.isUrlAllowed(g.endpointUrl) ? "IN_SCOPE" : "OUT_OF_SCOPE",
        },
        update: {
          assetId: asset.id, schemaAvailable: g.schemaAvailable, queries: g.queries,
          mutations: g.mutations, subscriptions: g.subscriptions, types: g.types,
          authenticationRequired: g.authenticationRequired, source: g.source,
        },
      });
    }

    // Endpoints (§37): written directly (never through URL
    // canonicalization) so `{id}` path templates survive intact.
    const operationByKey = new Map(result.operations.map((op) => [`${op.method} ${op.path}`, op]));
    let endpointCount = 0;
    for (const ep of result.endpoints) {
      const method = ep.method ?? "GET";
      const source = ep.source ?? result.specification.source;
      const asset = await this.resolveAsset(workspace.id, targetId, hostOf(ep.url));
      const path = pathTemplateOf(ep.url);
      const op = operationByKey.get(`${method} ${path}`)
        ?? [...operationByKey.values()].find((o) => o.method === method && path.endsWith(o.path));
      const scopeStatus = matcher.isUrlAllowed(ep.url.replace(/\{[^}]+\}/g, "1")) ? "IN_SCOPE" : "OUT_OF_SCOPE";
      const apiFields = {
        endpointType: "API" as const,
        operationId: op?.operationId, path,
        contentTypes: op?.contentTypes ?? [],
        authRequired: op?.authRequired, authSchemes: op?.authSchemes ?? [],
      };
      const existing = await this.prisma.endpoint.findFirst({ where: { assetId: asset.id, url: ep.url, method } });
      const row = existing
        ? await this.prisma.endpoint.update({
            where: { id: existing.id },
            data: { ...apiFields, sources: [...new Set([...(existing.sources ?? []), source])], scopeStatus },
          })
        : await this.prisma.endpoint.create({
            data: {
              assetId: asset.id, url: ep.url, method, source,
              sources: [source], scopeStatus, ...apiFields,
            },
          });
      for (const name of ep.parameterNames ?? []) {
        const found = await this.prisma.endpointParameter.findFirst({ where: { endpointId: row.id, name } });
        if (!found) {
          await this.prisma.endpointParameter.create({
            data: { endpointId: row.id, name, location: "UNKNOWN", sources: [source], confidence: 0.9 },
          });
        }
      }
      endpointCount++;
    }

    const policy = new ApiOperationPolicyEngine();
    const blocked = result.operations.filter((op) => policy.classify(op).classification !== "SAFE").length;
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "API_SPEC_IMPORTED", resourceType: "ApiSpecification", resourceId: specification.id,
      metadata: {
        kind: result.specification.kind, operations: result.operations.length,
        blockedOperations: blocked, endpoints: endpointCount, checksum,
      },
    });
    return {
      workspaceId: workspace.id,
      specificationId: specification.id, kind: result.specification.kind,
      services: result.apiServices.length + result.graphqlServices.length,
      endpoints: endpointCount, operations: result.operations.length,
      blockedOperations: blocked, schemas: schemaCount,
      warnings: result.warnings, secretReferences: [],
    };
  }

  private async resolveAsset(workspaceId: string, targetId: string, host: string) {
    const existing = await this.prisma.asset.findFirst({ where: { targetId, host } });
    if (existing) return existing;
    return this.prisma.asset.create({
      data: { workspaceId, targetId, host, type: "HOST", scopeStatus: "IN_SCOPE", sources: [] },
    });
  }

  private async scopeMatcherFor(targetId: string, targetValue: string): Promise<ScopeMatcher> {
    const assessment = await this.prisma.assessment.findFirst({
      where: { targetId }, orderBy: { createdAt: "desc" }, include: { scope: true },
    });
    const parsed = scopeRulesSchema.safeParse((assessment?.scope as { rules?: unknown } | null)?.rules ?? {});
    const rules: ScopeRules = parsed.success
      ? parsed.data
      : { includeHosts: [hostOf(targetValue), `*.${hostOf(targetValue)}`], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] };
    return new ScopeMatcher(rules);
  }

  // ------------------------------ inventory ------------------------------

  async listServices(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const [rest, graphql] = await Promise.all([
      this.prisma.apiService.findMany({ where: { workspaceId: workspace.id }, orderBy: { baseUrl: "asc" } }),
      this.prisma.graphqlService.findMany({ where: { workspaceId: workspace.id }, orderBy: { endpointUrl: "asc" } }),
    ]);
    return { rest, graphql };
  }

  async getService(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const service = await this.prisma.apiService.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!service) throw new NotFoundException("API service not found");
    const endpoints = await this.prisma.endpoint.findMany({
      where: { assetId: service.assetId, endpointType: "API" }, orderBy: { url: "asc" }, take: 500,
    });
    return { service, endpoints };
  }

  async listEndpoints(user: RequestUser, query: { page: number; pageSize: number; method?: string; search?: string }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const where: Record<string, unknown> = { asset: { workspaceId: workspace.id }, endpointType: "API" };
    if (query.method) where.method = query.method.toUpperCase();
    if (query.search) where.url = { contains: query.search };
    const [items, total] = await Promise.all([
      this.prisma.endpoint.findMany({
        where, orderBy: { url: "asc" },
        skip: (query.page - 1) * query.pageSize, take: query.pageSize,
        include: { parameters: { select: { name: true, location: true } } },
      }),
      this.prisma.endpoint.count({ where }),
    ]);
    return { items, total, page: query.page, pageSize: query.pageSize };
  }

  async getEndpoint(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const endpoint = await this.prisma.endpoint.findFirst({
      where: { id, asset: { workspaceId: workspace.id } },
      include: { parameters: true, forms: true },
    });
    if (!endpoint) throw new NotFoundException("Endpoint not found");
    const [requestSchema, responseSchema] = await Promise.all([
      endpoint.requestSchemaId ? this.prisma.apiSchema.findUnique({ where: { id: endpoint.requestSchemaId } }) : null,
      endpoint.responseSchemaId ? this.prisma.apiSchema.findUnique({ where: { id: endpoint.responseSchemaId } }) : null,
    ]);
    return { endpoint, requestSchema, responseSchema };
  }

  async listGraphql(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.graphqlService.findMany({ where: { workspaceId: workspace.id }, orderBy: { endpointUrl: "asc" } });
  }

  async listWebSockets(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.webSocketEndpoint.findMany({ where: { workspaceId: workspace.id }, orderBy: { url: "asc" }, take: 500 });
  }

  async listJwtProfiles(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    // Metadata + redacted claims only — the model has no token column.
    return this.prisma.jwtProfile.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  async listSpecifications(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.apiSpecification.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  async summary(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const ws = workspace.id;
    const [services, graphql, endpoints, specifications, webSockets, jwtProfiles, findings] = await Promise.all([
      this.prisma.apiService.count({ where: { workspaceId: ws } }),
      this.prisma.graphqlService.count({ where: { workspaceId: ws } }),
      this.prisma.endpoint.count({ where: { asset: { workspaceId: ws }, endpointType: "API" } }),
      this.prisma.apiSpecification.count({ where: { workspaceId: ws } }),
      this.prisma.webSocketEndpoint.count({ where: { workspaceId: ws } }),
      this.prisma.jwtProfile.count({ where: { workspaceId: ws } }),
      this.prisma.finding.findMany({ where: { workspaceId: ws, vulnClass: { in: API_VULN_CLASSES } }, select: { vulnClass: true, severity: true } }),
    ]);
    const findingsByClass: Record<string, number> = {};
    for (const f of findings) if (f.vulnClass) findingsByClass[f.vulnClass] = (findingsByClass[f.vulnClass] ?? 0) + 1;
    return {
      apiServices: services, graphqlServices: graphql, apiEndpoints: endpoints,
      specifications, webSockets, jwtProfiles,
      findingsTotal: findings.length, findingsByClass,
    };
  }

  // ------------------------------ JWT inspection ------------------------------

  /** Stateless analyst inspection (§22–§25): decode + claim/algorithm
   *  observations. NOTHING is persisted; the audit record carries the
   *  fingerprint only. Profiles from scans persist via the worker. */
  async inspectJwt(user: RequestUser, input: { token: string; host?: string; endpoint?: string }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const adapter = new JwtToolAdapter();
    let parsed;
    try {
      parsed = adapter.inspectTokens({
        tokens: [input.token],
        ...(input.host ? { host: input.host } : {}),
        ...(input.endpoint ? { endpoint: input.endpoint } : {}),
      });
    } catch {
      throw new BadRequestException("Token could not be inspected (oversized or malformed)");
    }
    const profile = parsed.jwtProfiles[0];
    if (!profile) throw new BadRequestException("Token is not a decodable JWT");
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "JWT_ANALYZED", resourceType: "JwtProfile", resourceId: profile.fingerprint,
      metadata: { algorithm: profile.algorithm, findings: parsed.findings.length },
    });
    return {
      profile,
      observations: parsed.findings.map((f) => ({
        title: f.title, severity: f.severity, vulnClass: (f as { vulnClass?: string }).vulnClass,
        description: f.description, remediation: f.remediation,
      })),
    };
  }

  // ------------------------------ records (architecture) ------------------------------

  async listAuthorizationTestCases(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.authorizationTestCase.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  /** §42–§45: a case is a reviewed DESIGN record — identity A vs
   *  identity B contexts over an object-identifier TEMPLATE (never a
   *  real user's id). Creating one never approves it and nothing here
   *  executes it — controlled validation belongs to a later phase
   *  behind its own approval gate. */
  async createAuthorizationTestCase(user: RequestUser, input: {
    endpointId?: string; objectIdentifier?: string;
    identityAContextId?: string; identityBContextId?: string; expectedAccess?: string;
  }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    for (const contextId of [input.identityAContextId, input.identityBContextId]) {
      if (!contextId) continue;
      const ctx = await this.prisma.apiAuthContext.findFirst({ where: { id: contextId, workspaceId: workspace.id } });
      if (!ctx) throw new NotFoundException("API auth context not found in this workspace");
    }
    const row = await this.prisma.authorizationTestCase.create({
      data: {
        workspaceId: workspace.id, endpointId: input.endpointId,
        objectIdentifier: input.objectIdentifier,
        identityAContextId: input.identityAContextId, identityBContextId: input.identityBContextId,
        expectedAccess: input.expectedAccess,
        createdBy: user.id, approvalStatus: "NOT_APPROVED",
      },
    });
    return row;
  }

  async listTestDataProfiles(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.testDataProfile.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  /** §18: test data uses placeholders or secret REFERENCES — a value
   *  under a secret-named key that is not an ALL-CAPS reference name is
   *  rejected outright. */
  async createTestDataProfile(user: RequestUser, input: { name: string; description?: string; data?: Record<string, unknown> }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    for (const [key, value] of Object.entries(input.data ?? {})) {
      if (isSecretLikeKey(key) && typeof value === "string" && !REFERENCE_NAME.test(value)) {
        throw new BadRequestException(`Test data field "${key}" looks like a secret — use a placeholder or a secret reference name`);
      }
    }
    return this.prisma.testDataProfile.create({
      data: {
        workspaceId: workspace.id, name: input.name, description: input.description,
        values: (input.data ?? {}) as never, createdBy: user.id,
      },
    });
  }

  async listApiAuthContexts(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.apiAuthContext.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  /** §19–§21: contexts bind a test ROLE (ANONYMOUS / USER_A / USER_B /
   *  ADMIN_TEST) to a session profile + a credential REFERENCE NAME.
   *  A URL or raw secret can never be stored here. */
  async createApiAuthContext(user: RequestUser, input: {
    role: string; credentialReference?: string; sessionProfileId?: string; apiServiceId?: string;
  }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    if (input.credentialReference !== undefined && !REFERENCE_NAME.test(input.credentialReference)) {
      throw new BadRequestException("credentialReference must be a reference NAME (e.g. API_USER_A_TOKEN), never a value or URL");
    }
    return this.prisma.apiAuthContext.create({
      data: {
        workspaceId: workspace.id, role: input.role,
        credentialReference: input.credentialReference, sessionProfileId: input.sessionProfileId,
        apiServiceId: input.apiServiceId, createdBy: user.id,
      },
    });
  }
}
