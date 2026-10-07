/**
 * Controlled API test fixtures (Prompt 9 §68): a small, fully local,
 * DOCUMENTED fake API surface used by the SDK/worker test suites. Every
 * value here is obviously fake (example.com, test users, FAKE
 * signatures). No fixture ever points at a real system, and no real
 * credential appears anywhere — JWT fixtures are unsigned test tokens
 * built by makeFakeJwt with the literal signature "FAKE-SIGNATURE".
 */

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Build an obviously-fake JWT for inspection tests: real structure,
 *  fake signature segment, test-only claims (§70). */
export function makeFakeJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  return `${b64url(header)}.${b64url(payload)}.FAKE-SIGNATURE`;
}

const NOW = Math.floor(Date.now() / 1000);

/** Well-configured token: RS256, 1h lifetime, no sensitive claims. */
export const FIXTURE_JWT_GOOD = makeFakeJwt(
  { alg: "RS256", typ: "JWT", kid: "test-key-1" },
  { sub: "test-user-a", iss: "https://auth.example.com", aud: "dsrclone-test-api", iat: NOW - 60, exp: NOW + 3600, scope: "read:users" },
);
/** 'none' algorithm + sensitive claim + no expiry: three findings. */
export const FIXTURE_JWT_BAD = makeFakeJwt(
  { alg: "none", typ: "JWT" },
  { sub: "test-user-b", iss: "https://auth.example.com", password: "FAKE-test-password-not-real", role: "user" },
);
/** Excessive lifetime (90 days) with a symmetric algorithm. */
export const FIXTURE_JWT_LONG_LIVED = makeFakeJwt(
  { alg: "HS256", typ: "JWT" },
  { sub: "test-user-a", iss: "https://auth.example.com", iat: NOW - 60, exp: NOW + 90 * 24 * 3600 },
);

export const FIXTURE_OPENAPI = {
  openapi: "3.0.3",
  info: { title: "DSRclone Fixture API", version: "1.2.0", description: "Controlled local test API (fixtures only)." },
  servers: [{ url: "https://api.example.com/v1" }],
  security: [{ BearerAuth: [] }],
  components: {
    securitySchemes: { BearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" } },
    schemas: {
      User: {
        type: "object",
        required: ["id", "email"],
        properties: {
          id: { type: "integer", format: "int64" },
          email: { type: "string", format: "email" },
          profile: { type: "object", properties: { name: { type: "string" }, bio: { type: "string" } } },
        },
      },
      NewUser: {
        type: "object",
        required: ["email"],
        properties: { email: { type: "string", format: "email" }, name: { type: "string" } },
      },
    },
  },
  paths: {
    "/users": {
      get: { operationId: "listUsers", responses: { "200": { description: "ok", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/User" } } } } } } },
      post: {
        operationId: "createUser",
        requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/NewUser" } } } },
        responses: { "201": { description: "created" } },
      },
    },
    "/users/{id}": {
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
      get: { operationId: "getUser", responses: { "200": { description: "ok", content: { "application/json": { schema: { $ref: "#/components/schemas/User" } } } } } },
      delete: { operationId: "deleteUser", responses: { "204": { description: "deleted" } } },
    },
    "/auth/login": {
      post: {
        operationId: "login", security: [],
        requestBody: { content: { "application/json": { schema: { type: "object", properties: { username: { type: "string" }, password: { type: "string", format: "password" } } } } } },
        responses: { "200": { description: "ok" } },
      },
    },
    "/payments/checkout": {
      post: { operationId: "checkout", requestBody: { content: { "application/json": { schema: { type: "object", properties: { amount: { type: "number" } } } } } }, responses: { "200": { description: "ok" } } },
    },
    "/health": {
      get: { operationId: "health", security: [], responses: { "200": { description: "ok" } } },
    },
  },
};

export const FIXTURE_OPENAPI_JSON = JSON.stringify(FIXTURE_OPENAPI, null, 2);

export const FIXTURE_OPENAPI_YAML = [
  "openapi: 3.0.3",
  "info:",
  "  title: Fixture YAML API",
  "  version: '0.1.0'",
  "servers:",
  "  - url: https://api.example.com/yaml/v1",
  "paths:",
  "  /status:",
  "    get:",
  "      operationId: yamlStatus",
  "      responses:",
  "        '200':",
  "          description: ok",
  "",
].join("\n");

/** §74 hostile YAML: a custom js/function tag must be REJECTED by the
 *  JSON_SCHEMA-only parser, never executed or interpreted. */
export const FIXTURE_HOSTILE_YAML = [
  "openapi: 3.0.3",
  "info: { title: Hostile, version: '1.0' }",
  "x-evil: !!js/function 'function () { return 1; }'",
  "paths: {}",
  "",
].join("\n");

/** §74 hostile OpenAPI: external $refs (never fetched) + a script-like
 *  description (stored as data, length/control-char sanitized). */
export const FIXTURE_HOSTILE_OPENAPI_JSON = JSON.stringify({
  openapi: "3.0.3",
  info: { title: "Hostile Fixture", version: "1.0", description: "<script>alert(1)</script> =cmd|' /C calc'!A0" },
  servers: [{ url: "https://api.example.com/v1" }],
  paths: {
    "/ext": {
      get: {
        operationId: "extRef",
        responses: { "200": { description: "ok", content: { "application/json": { schema: { $ref: "https://schemas.evil.example.com/payload.json" } } } } },
      },
    },
  },
});

export const FIXTURE_POSTMAN_COLLECTION = JSON.stringify({
  info: { name: "DSRclone Fixture Collection", schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  auth: { type: "bearer" },
  variable: [
    { key: "baseUrl", value: "https://api.example.com" },
    { key: "api_token", value: "FAKE-postman-secret-token-value" },
  ],
  item: [
    {
      name: "Users",
      item: [
        {
          name: "List users",
          request: {
            method: "GET",
            url: "{{baseUrl}}/users?limit=10",
            header: [{ key: "Accept", value: "application/json" }, { key: "Authorization", value: "Bearer FAKE" }],
          },
        },
        {
          name: "Create user",
          request: {
            method: "POST",
            url: { raw: "{{baseUrl}}/users", host: ["api", "example", "com"], path: ["users"] },
            body: { mode: "raw", raw: JSON.stringify({ email: "rudra@example.com", profile: { name: "Rudra" } }) },
          },
        },
      ],
    },
    {
      name: "Get user",
      request: { method: "GET", url: "{{baseUrl}}/users/:id" },
    },
  ],
}, null, 2);

export const FIXTURE_POSTMAN_ENVIRONMENT = JSON.stringify({
  name: "Fixture Environment",
  values: [
    { key: "baseUrl", value: "https://api.example.com", enabled: true, type: "default" },
    { key: "api_token", value: "FAKE-env-secret", enabled: true, type: "secret" },
    { key: "region", value: "test", enabled: true, type: "default" },
  ],
}, null, 2);

export const FIXTURE_INSOMNIA_EXPORT = JSON.stringify({
  _type: "export",
  __export_format: 4,
  resources: [
    { _id: "wrk_fixture", _type: "workspace", name: "Fixture Workspace" },
    {
      _id: "env_fixture", _type: "environment", name: "Base",
      data: { base_url: "https://api.example.com", api_secret: "FAKE-insomnia-secret" },
    },
    {
      _id: "req_1", _type: "request", name: "List orders", method: "GET",
      url: "{{ _.base_url }}/orders",
      parameters: [{ name: "status", value: "open" }],
      headers: [{ name: "Accept", value: "application/json" }],
      authentication: { type: "bearer token" },
    },
    {
      _id: "req_2", _type: "request", name: "Create order", method: "POST",
      url: "{{ _.base_url }}/orders",
      body: { mimeType: "application/x-www-form-urlencoded", params: [{ name: "item_id", value: "42" }, { name: "quantity", value: "1" }] },
    },
  ],
}, null, 2);

export const FIXTURE_GRAPHQL_INTROSPECTION = JSON.stringify({
  data: {
    __schema: {
      queryType: { name: "Query" },
      mutationType: { name: "Mutation" },
      subscriptionType: null,
      types: [
        { name: "Query", kind: "OBJECT", fields: [{ name: "user" }, { name: "users" }, { name: "health" }] },
        { name: "Mutation", kind: "OBJECT", fields: [{ name: "createUser" }, { name: "deleteUser" }] },
        { name: "User", kind: "OBJECT", fields: [{ name: "id" }, { name: "email" }] },
        { name: "String", kind: "SCALAR", fields: null },
        { name: "__Schema", kind: "OBJECT", fields: [] },
      ],
    },
  },
}, null, 2);

export const FIXTURE_KITERUNNER_JSONL = [
  JSON.stringify({ method: "GET", path: "/users", statusCode: 200, headers: { "content-type": "application/json" } }),
  JSON.stringify({ method: "GET", path: "/openapi.json", statusCode: 200, headers: { "content-type": "application/json" } }),
  JSON.stringify({ method: "POST", path: "/auth/login", statusCode: 401, headers: { "content-type": "application/json" } }),
  "this line is not json — parser must warn, not fail",
].join("\n");

export const FIXTURE_SCHEMATHESIS_JUNIT = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  "<testsuites>",
  '  <testsuite name="schemathesis" tests="3" failures="2">',
  '    <testcase classname="GET https://api.example.com/v1/users not_a_server_error" name="test_no_server_error[GET /users]">',
  '      <failure message="Received response with status 500">AssertionError: 500</failure>',
  "    </testcase>",
  '    <testcase classname="GET https://api.example.com/v1/users response_schema_conformance" name="test_schema[GET /users]">',
  '      <failure message="Response body does not match schema">SchemaMismatch</failure>',
  "    </testcase>",
  '    <testcase classname="GET https://api.example.com/v1/health status_code_conformance" name="test_status[GET /health]" />',
  "  </testsuite>",
  "</testsuites>",
].join("\n");

/** mitmproxy JSON flow dump (§33): two HTTP flows + one WebSocket
 *  handshake. Authorization/Cookie header values are fixture fakes and
 *  are redacted by the parser before anything is stored. */
export const FIXTURE_MITMPROXY_FLOWS = JSON.stringify([
  {
    id: "flow-1", type: "http",
    request: {
      method: "GET", scheme: "https", host: "api.example.com", port: 443, path: "/v1/users?limit=10",
      http_version: "HTTP/2.0",
      headers: [["host", "api.example.com"], ["authorization", "Bearer FAKE-FIXTURE-TOKEN"], ["accept", "application/json"]],
      content: "",
    },
    response: { status_code: 200, http_version: "HTTP/2.0", headers: [["content-type", "application/json"]], content: "" },
  },
  {
    id: "flow-2", type: "http",
    request: {
      method: "POST", scheme: "https", host: "api.example.com", port: 443, path: "/v1/users",
      http_version: "HTTP/2.0",
      headers: [["host", "api.example.com"], ["content-type", "application/json"], ["cookie", "session=FAKE-FIXTURE"]],
      content: "",
    },
    response: { status_code: 201, http_version: "HTTP/2.0", headers: [["content-type", "application/json"]], content: "" },
  },
  {
    id: "flow-3", type: "http",
    request: {
      method: "GET", scheme: "wss", host: "api.example.com", port: 443, path: "/v1/stream",
      http_version: "HTTP/1.1",
      headers: [["host", "api.example.com"], ["upgrade", "websocket"], ["sec-websocket-protocol", "v1.stream"]],
      content: "",
    },
    response: { status_code: 101, http_version: "HTTP/1.1", headers: [["upgrade", "websocket"]], content: "" },
    websocket: { messages: [], closed_by_client: false },
  },
], null, 2);

/** Tool-output fixtures keyed by executable for FixtureToolRunner. */
export function buildApiFixtures(): Record<string, import("../recon/runner").FixtureResponse> {
  return {
    kr: { stdout: FIXTURE_KITERUNNER_JSONL },
    schemathesis: { stdout: FIXTURE_SCHEMATHESIS_JUNIT },
    inql: { stdout: FIXTURE_GRAPHQL_INTROSPECTION },
    graphqlmap: { stdout: "GraphQL endpoint found: https://api.example.com/graphql — introspection enabled (graphql-ruby)" },
  };
}
