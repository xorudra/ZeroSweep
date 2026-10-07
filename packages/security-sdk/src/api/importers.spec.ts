import { describe, expect, it } from "vitest";
import {
  GraphqlSchemaImporter, InsomniaImporter, OpenApiImporter, PostmanCollectionImporter, parsePostmanEnvironment,
} from "./importers";
import { parseSpecDocument, SpecImportError } from "./import-security";
import {
  FIXTURE_GRAPHQL_INTROSPECTION, FIXTURE_HOSTILE_OPENAPI_JSON, FIXTURE_HOSTILE_YAML,
  FIXTURE_INSOMNIA_EXPORT, FIXTURE_OPENAPI_JSON, FIXTURE_OPENAPI_YAML,
  FIXTURE_POSTMAN_COLLECTION, FIXTURE_POSTMAN_ENVIRONMENT,
} from "./fixtures";

/**
 * Specification importers (Prompt 9 §6–§12, §29, §66, §69, §74):
 * inventory extraction from OpenAPI/Swagger/Postman/Insomnia/GraphQL
 * documents, with hostile-input proof — malformed, oversized,
 * recursive, unsafe-YAML and secret-bearing documents must never yield
 * stored secrets, fetched references or parser exhaustion.
 */
const openapi = new OpenApiImporter();

describe("OpenApiImporter (§8, §69)", () => {
  const result = openapi.parse(FIXTURE_OPENAPI_JSON, { source: "test-import" });

  it("extracts services, operations, endpoints, parameters and schemas", () => {
    expect(result.apiServices).toHaveLength(1);
    expect(result.apiServices[0]).toMatchObject({ baseUrl: "https://api.example.com/v1", apiType: "REST", authenticationType: "BEARER" });
    expect(result.specification.kind).toBe("OPENAPI");
    expect(result.specification.operationCount).toBe(7);
    const ops = result.operations.map((o) => `${o.method} ${o.path}`);
    expect(ops).toContain("GET /users");
    expect(ops).toContain("DELETE /users/{id}");
    const getUser = result.endpoints.find((e) => e.url === "https://api.example.com/v1/users/{id}" && e.method === "GET");
    expect(getUser?.endpointType).toBe("API");
    // Path parameter from the path-item level is attached (§8).
    expect(result.parameters.some((p) => p.name === "id" && p.location === "PATH")).toBe(true);
    // Request-body property paths are extracted as BODY parameters (§35).
    const bodyParams = result.parameters.filter((p) => p.location === "BODY").map((p) => p.name);
    expect(bodyParams).toContain("email");
    expect(bodyParams).toContain("username");
    // Nested response-schema paths are schema structure (§36): the User
    // component records profile.name without inventing parameters.
    expect(result.schemas.find((s) => s.name === "User")?.properties.profile).toBe("object");
    // Component schemas stored once with structure only (§36).
    const userSchema = result.schemas.find((s) => s.name === "User");
    expect(userSchema?.requiredFields).toEqual(["id", "email"]);
    expect(userSchema?.properties.email).toBe("string(email)");
  });

  it("records declared authentication per operation (§8/§19)", () => {
    const login = result.operations.find((o) => o.operationId === "login");
    expect(login?.authRequired).toBe(false); // explicitly security: []
    const listUsers = result.operations.find((o) => o.operationId === "listUsers");
    expect(listUsers?.authRequired).toBe(true);
    expect(listUsers?.authSchemes).toContain("BearerAuth");
    expect(result.securitySchemes).toEqual([{ name: "BearerAuth", type: "http", scheme: "bearer" }]);
  });

  it("produces NO findings — imports are inventory (§51)", () => {
    expect(result).not.toHaveProperty("findings");
    expect(result.specification.checksum).toMatch(/^[a-f0-9]{64}$/);
    expect(result.specification.artifactRef).toContain("api-specs/");
  });

  it("parses YAML OpenAPI through the guarded YAML path", () => {
    const yaml = openapi.parse(FIXTURE_OPENAPI_YAML, { source: "t" });
    expect(yaml.operations).toHaveLength(1);
    expect(yaml.apiServices[0]?.baseUrl).toBe("https://api.example.com/yaml/v1");
  });

  it("rejects documents that are not OpenAPI/Swagger", () => {
    expect(() => openapi.parse(JSON.stringify({ hello: "world" }), { source: "t" })).toThrow(SpecImportError);
    expect(() => openapi.parse("not json at all {{{", { source: "t" })).toThrow(SpecImportError);
  });
});

describe("Hostile specification handling (§7/§66/§74)", () => {
  it("rejects unsafe YAML (custom tags are never interpreted)", () => {
    expect(() => parseSpecDocument(FIXTURE_HOSTILE_YAML)).toThrow(SpecImportError);
  });

  it("rejects oversized documents before parsing", () => {
    const big = JSON.stringify({ openapi: "3.0.3", info: { title: "x".repeat(6_000), version: "1" }, paths: {} });
    expect(() => parseSpecDocument(big, { maxBytes: 1024 })).toThrow(/exceeding the import limit/);
  });

  it("rejects pathological nesting (parser exhaustion)", () => {
    let nested: unknown = { leaf: true };
    for (let i = 0; i < 60; i++) nested = { a: nested };
    expect(() => parseSpecDocument(JSON.stringify(nested))).toThrow(/nesting depth/);
  });

  it("collects external $refs but NEVER fetches them", () => {
    const result = openapi.parse(FIXTURE_HOSTILE_OPENAPI_JSON, { source: "t" });
    expect(result.warnings.some((w) => w.includes("NOT fetched"))).toBe(true);
    // The external-ref operation still imports as inventory; the
    // unresolved schema contributes no fabricated parameters.
    expect(result.operations.map((o) => o.operationId)).toContain("extRef");
    // Script-like description text is stored as inert data (sanitized).
    expect(JSON.stringify(result)).not.toContain("\u0000");
  });

  it("detects recursive local references without hanging", () => {
    const recursive = JSON.stringify({
      openapi: "3.0.3", info: { title: "Recursive", version: "1" },
      servers: [{ url: "https://api.example.com" }],
      components: { schemas: { Node: { type: "object", properties: { child: { $ref: "#/components/schemas/Node" } } } } },
      paths: { "/nodes": { get: { operationId: "nodes", responses: { "200": { description: "ok", content: { "application/json": { schema: { $ref: "#/components/schemas/Node" } } } } } } } },
    });
    const result = openapi.parse(recursive, { source: "t" });
    expect(result.operations).toHaveLength(1);
  });
});

describe("PostmanCollectionImporter (§10/§11)", () => {
  const result = new PostmanCollectionImporter().parse(FIXTURE_POSTMAN_COLLECTION, { source: "postman" });

  it("extracts requests as operations + endpoints with provenance", () => {
    expect(result.specification.kind).toBe("POSTMAN_COLLECTION");
    expect(result.operations).toHaveLength(3);
    expect(result.endpoints.map((e) => e.url)).toContain("https://api.example.com/users");
    // Postman :id path params become {id} templates.
    expect(result.endpoints.map((e) => e.url)).toContain("https://api.example.com/users/{id}");
    expect(result.apiServices[0]?.authenticationType).toBe("BEARER");
  });

  it("drops secret variable VALUES — counted, never present (§11)", () => {
    expect(result.secretsRedacted).toBe(1);
    expect(JSON.stringify(result)).not.toContain("FAKE-postman-secret-token-value");
    expect(JSON.stringify(result)).not.toContain("Bearer FAKE");
    expect(result.warnings.some((w) => w.includes("secret references"))).toBe(true);
  });

  it("extracts body structure from examples without storing values", () => {
    const bodyParams = result.parameters.filter((p) => p.location === "BODY").map((p) => p.name);
    expect(bodyParams).toContain("email");
    expect(bodyParams).toContain("profile.name");
    expect(JSON.stringify(result.parameters)).not.toContain("rudra@example.com");
  });

  it("parses environments into names + secret classification only", () => {
    const env = parsePostmanEnvironment(FIXTURE_POSTMAN_ENVIRONMENT);
    expect(env.variables).toEqual([
      { key: "baseUrl", secret: false },
      { key: "api_token", secret: true },
      { key: "region", secret: false },
    ]);
    expect(env.secretsRedacted).toBe(1);
    expect(JSON.stringify(env)).not.toContain("FAKE-env-secret");
  });
});

describe("InsomniaImporter (§12)", () => {
  const result = new InsomniaImporter().parse(FIXTURE_INSOMNIA_EXPORT, { source: "insomnia" });

  it("extracts requests, parameters and auth metadata", () => {
    expect(result.specification.kind).toBe("INSOMNIA_EXPORT");
    expect(result.operations).toHaveLength(2);
    const listOrders = result.operations.find((o) => o.path === "/orders" && o.method === "GET");
    expect(listOrders?.authRequired).toBe(true);
    expect(result.parameters.some((p) => p.name === "status" && p.location === "QUERY")).toBe(true);
    expect(result.parameters.some((p) => p.name === "item_id" && p.location === "BODY")).toBe(true);
  });

  it("drops secret environment values", () => {
    expect(result.secretsRedacted).toBe(1);
    expect(JSON.stringify(result)).not.toContain("FAKE-insomnia-secret");
  });
});

describe("GraphqlSchemaImporter (§29)", () => {
  const result = new GraphqlSchemaImporter().parse(FIXTURE_GRAPHQL_INTROSPECTION, { source: "graphql-import", endpointUrl: "https://api.example.com/graphql" });

  it("builds GraphQL inventory: counts, types, and the mutation warning", () => {
    expect(result.graphqlServices).toHaveLength(1);
    const svc = result.graphqlServices[0]!;
    expect(svc).toMatchObject({ endpointUrl: "https://api.example.com/graphql", schemaAvailable: true, queries: 3, mutations: 2, subscriptions: 0 });
    // Introspection types (__Schema) are excluded from the type count.
    expect(svc.types).toBe(4);
    expect(result.warnings.some((w) => w.includes("NOT automatically tested"))).toBe(true);
    expect(result.apiServices[0]?.apiType).toBe("GRAPHQL");
  });

  it("rejects documents without an introspection schema", () => {
    expect(() => new GraphqlSchemaImporter().parse(JSON.stringify({ data: {} }), { source: "t", endpointUrl: "https://api.example.com/graphql" })).toThrow(SpecImportError);
  });
});
