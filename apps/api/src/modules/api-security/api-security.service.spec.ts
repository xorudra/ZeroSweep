import { BadRequestException, NotFoundException } from "@nestjs/common";
import {
  FIXTURE_GRAPHQL_INTROSPECTION, FIXTURE_HOSTILE_OPENAPI_JSON, FIXTURE_JWT_BAD,
  FIXTURE_OPENAPI_JSON, FIXTURE_POSTMAN_COLLECTION, FIXTURE_POSTMAN_ENVIRONMENT,
} from "@zerosweep/security-sdk";
import { ApiSecurityService } from "./api-security.service";

/**
 * Prompt 9 API service (§67/§69/§74): guarded imports produce INVENTORY
 * ONLY (never findings), secrets never persist (names become
 * references), JWT inspection never stores the token, and every view
 * is tenant-isolated. Fake Prisma — no database, no network.
 */

const user = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

const SCOPE_RULES = {
  includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [],
  allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [],
};

interface Row { [k: string]: unknown }
let seq = 0;
const nid = (p: string) => `${p}-${++seq}`;

function makeFakePrisma() {
  const db = {
    assets: [] as Row[], specifications: [] as Row[], schemas: [] as Row[],
    services: [] as Row[], graphql: [] as Row[], endpoints: [] as Row[],
    parameters: [] as Row[], contexts: [] as Row[], cases: [] as Row[],
    profiles: [] as Row[], jwtProfiles: [] as Row[], webSockets: [] as Row[],
    findings: [] as Row[],
  };
  const match = (row: Row, where: Row = {}): boolean => Object.entries(where).every(([k, v]) => {
    if (k === "asset") {
      const asset = db.assets.find((a) => a.id === row.assetId);
      return !!asset && match(asset, (v as Row).workspaceId !== undefined ? { workspaceId: (v as Row).workspaceId } : v as Row);
    }
    if (v !== null && typeof v === "object") {
      const cond = v as Row;
      if ("in" in cond) return (cond.in as unknown[]).includes(row[k]);
      if ("contains" in cond) return typeof row[k] === "string" && (row[k] as string).includes(cond.contains as string);
      if ("notIn" in cond) return !(cond.notIn as unknown[]).includes(row[k]);
      return match(row[k] as Row, cond);
    }
    return row[k] === v;
  });
  const findIn = (rows: Row[]) => ({
    findMany: async (args: { where?: Row; take?: number } = {}) => {
      const out = rows.filter((r) => match(r, args.where));
      return args.take ? out.slice(0, args.take) : out;
    },
    findFirst: async (args: { where?: Row } = {}) => rows.find((r) => match(r, args.where)) ?? null,
    count: async (args: { where?: Row } = {}) => rows.filter((r) => match(r, args.where)).length,
    create: async (args: { data: Row }) => {
      const row = { id: nid("row"), createdAt: new Date(), updatedAt: new Date(), ...args.data };
      rows.push(row);
      return row;
    },
  });
  const prisma = {
    workspace: {
      findFirst: async (args: { where: Row }) =>
        args.where.organizationId === "org-1" ? { id: "ws-1", organizationId: "org-1" }
        : args.where.organizationId === "org-2" ? { id: "ws-2", organizationId: "org-2" } : null,
    },
    target: {
      findFirst: async (args: { where: Row }) =>
        args.where.id === "t-1" ? { id: "t-1", value: "api.example.com", type: "API", workspaceId: "ws-1" } : null,
    },
    assessment: {
      findFirst: async () => ({ id: "a-1", scope: { rules: SCOPE_RULES } }),
    },
    asset: {
      ...findIn(db.assets),
      findFirst: async (args: { where?: Row } = {}) => db.assets.find((r) => match(r, args.where)) ?? null,
    },
    apiSpecification: findIn(db.specifications),
    apiSchema: findIn(db.schemas),
    apiService: {
      ...findIn(db.services),
      upsert: async (args: { where: Row; create: Row; update: Row }) => {
        const key = (args.where as Row).assetId_baseUrl as Row;
        const found = db.services.find((s) => s.assetId === key.assetId && s.baseUrl === key.baseUrl);
        if (found) { Object.assign(found, args.update); return found; }
        const row = { id: nid("svc"), createdAt: new Date(), ...args.create };
        db.services.push(row);
        return row;
      },
    },
    graphqlService: {
      ...findIn(db.graphql),
      upsert: async (args: { where: Row; create: Row; update: Row }) => {
        const key = (args.where as Row).workspaceId_endpointUrl as Row;
        const found = db.graphql.find((g) => g.workspaceId === key.workspaceId && g.endpointUrl === key.endpointUrl);
        if (found) { Object.assign(found, args.update); return found; }
        const row = { id: nid("gql"), createdAt: new Date(), ...args.create };
        db.graphql.push(row);
        return row;
      },
    },
    endpoint: {
      ...findIn(db.endpoints),
      findMany: async (args: { where?: Row; take?: number; skip?: number } = {}) => {
        let out = db.endpoints.filter((r) => match(r, args.where));
        if (args.skip) out = out.slice(args.skip);
        if (args.take) out = out.slice(0, args.take);
        return out.map((e) => ({ ...e, parameters: db.parameters.filter((p) => p.endpointId === e.id), forms: [] }));
      },
      findFirst: async (args: { where?: Row } = {}) => db.endpoints.find((r) => match(r, args.where)) ?? null,
      update: async (args: { where: Row; data: Row }) => {
        const row = db.endpoints.find((r) => r.id === args.where.id)!;
        Object.assign(row, args.data);
        return row;
      },
    },
    endpointParameter: findIn(db.parameters),
    apiAuthContext: findIn(db.contexts),
    authorizationTestCase: findIn(db.cases),
    testDataProfile: findIn(db.profiles),
    jwtProfile: findIn(db.jwtProfiles),
    webSocketEndpoint: findIn(db.webSockets),
    finding: { findMany: async () => db.findings, count: async () => db.findings.length },
  };
  return { prisma, db };
}

function makeService() {
  const { prisma, db } = makeFakePrisma();
  const audits: Row[] = [];
  const audit = { record: async (e: Row) => { audits.push(e); } };
  const service = new ApiSecurityService(prisma as never, audit as never);
  return { service, db, audits };
}

describe("ApiSecurityService — guarded imports (§69/§74)", () => {
  it("imports an OpenAPI document into inventory ONLY — zero findings, blocked ops counted", async () => {
    const { service, db, audits } = makeService();
    const summary = await service.importOpenApi(user, { targetId: "t-1", content: FIXTURE_OPENAPI_JSON });
    expect(summary.operations).toBe(7);
    expect(summary.blockedOperations).toBeGreaterThanOrEqual(3);
    expect(summary.endpoints).toBe(7);
    expect(summary.services).toBe(1);
    expect(db.findings).toHaveLength(0);
    // Template URLs survive intact — no canonicalization damage.
    const templated = db.endpoints.find((e) => (e.url as string).includes("{id}"));
    expect(templated).toBeDefined();
    expect(templated!.operationId).toBe("getUser");
    expect(templated!.scopeStatus).toBe("IN_SCOPE");
    // State-changing operations are inventory too — recorded, blocked, never run.
    const audit = audits.find((a) => a.action === "API_SPEC_IMPORTED");
    expect(audit).toBeDefined();
    expect((audit!.metadata as Row).blockedOperations).toBe(summary.blockedOperations);
  });

  it("rejects oversize and malformed imports; hostile external $refs warn but never fetch", async () => {
    const { service } = makeService();
    await expect(service.importOpenApi(user, { targetId: "t-1", content: "x".repeat(10 * 1024 * 1024 + 1) }))
      .rejects.toBeInstanceOf(BadRequestException);
    await expect(service.importOpenApi(user, { targetId: "t-1", content: "{not json" }))
      .rejects.toBeInstanceOf(BadRequestException);
    const summary = await service.importOpenApi(user, { targetId: "t-1", content: FIXTURE_HOSTILE_OPENAPI_JSON });
    expect(summary.warnings.join(" ")).toMatch(/external/i);
  });

  it("Postman environment secrets become reference NAMES — values never persist", async () => {
    const { service, db } = makeService();
    const summary = await service.importPostman(user, {
      targetId: "t-1", content: FIXTURE_POSTMAN_COLLECTION, environment: FIXTURE_POSTMAN_ENVIRONMENT,
    });
    expect(summary.secretReferences).toContain("api_token");
    expect(JSON.stringify(db)).not.toContain("FAKE-env-secret");
  });

  it("imports a GraphQL introspection result as inventory + audit", async () => {
    const { service, db, audits } = makeService();
    const summary = await service.importGraphql(user, {
      targetId: "t-1", endpointUrl: "https://api.example.com/graphql", content: FIXTURE_GRAPHQL_INTROSPECTION,
    });
    // The GraphQL endpoint counts both as an API service and as a
    // GraphQL service record.
    expect(summary.services).toBe(2);
    expect(db.graphql).toHaveLength(1);
    expect(db.graphql[0]!.queries).toBe(3);
    expect(audits.some((a) => a.action === "GRAPHQL_SCHEMA_IMPORTED")).toBe(true);
  });
});

describe("ApiSecurityService — JWT inspection (§65/§70)", () => {
  it("returns fingerprint + observations; the raw token appears NOWHERE", async () => {
    const { service, audits } = makeService();
    const result = await service.inspectJwt(user, { token: FIXTURE_JWT_BAD, host: "api.example.com" });
    expect(result.profile.algorithm).toBe("none");
    expect(result.observations.map((o) => o.vulnClass)).toContain("JWT_ALGORITHM_CONFIGURATION");
    const serialized = JSON.stringify({ result, audits });
    expect(serialized).not.toContain(FIXTURE_JWT_BAD);
    expect(serialized).not.toContain("FAKE-test-password-not-real");
    const audit = audits.find((a) => a.action === "JWT_ANALYZED");
    expect((audit!.metadata as Row).algorithm).toBe("none");
  });

  it("rejects non-JWT input", async () => {
    const { service } = makeService();
    await expect(service.inspectJwt(user, { token: "not-a-jwt" })).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe("ApiSecurityService — tenant isolation (§67)", () => {
  it("foreign workspaces see nothing and foreign ids are 404s", async () => {
    const { service } = makeService();
    await service.importOpenApi(user, { targetId: "t-1", content: FIXTURE_OPENAPI_JSON });
    const foreignServices = await service.listServices(foreign);
    expect(foreignServices.rest).toHaveLength(0);
    expect(foreignServices.graphql).toHaveLength(0);
    const own = await service.listServices(user);
    await expect(service.getService(foreign, own.rest[0]!.id as string)).rejects.toBeInstanceOf(NotFoundException);
    const summary = await service.summary(foreign);
    expect(summary.apiServices).toBe(0);
  });
});

describe("ApiSecurityService — records (§18–§21, §42)", () => {
  it("auth contexts accept reference NAMES only", async () => {
    const { service } = makeService();
    await expect(service.createApiAuthContext(user, { role: "USER_A", credentialReference: "https://evil.example/steal" }))
      .rejects.toBeInstanceOf(BadRequestException);
    await expect(service.createApiAuthContext(user, { role: "USER_A", credentialReference: "raw-secret-value" }))
      .rejects.toBeInstanceOf(BadRequestException);
    const row = await service.createApiAuthContext(user, { role: "USER_A", credentialReference: "API_USER_A_TOKEN" });
    expect(row.credentialReference).toBe("API_USER_A_TOKEN");
  });

  it("test-data profiles reject secret-looking values but accept references", async () => {
    const { service } = makeService();
    await expect(service.createTestDataProfile(user, { name: "p", data: { password: "hunter2" } }))
      .rejects.toBeInstanceOf(BadRequestException);
    const row = await service.createTestDataProfile(user, { name: "p", data: { password: "API_TEST_PASSWORD_REF" } });
    expect(row.name).toBe("p");
  });

  it("authorization test cases are born NOT_APPROVED and validate their contexts", async () => {
    const { service } = makeService();
    const ctx = await service.createApiAuthContext(user, { role: "USER_A", credentialReference: "API_USER_A_TOKEN" });
    const testCase = await service.createAuthorizationTestCase(user, {
      objectIdentifier: "{userId}", identityAContextId: ctx.id as string, expectedAccess: "DENIED",
    });
    expect(testCase.approvalStatus).toBe("NOT_APPROVED");
    await expect(service.createAuthorizationTestCase(user, { identityAContextId: "foreign-ctx" }))
      .rejects.toBeInstanceOf(NotFoundException);
  });
});
