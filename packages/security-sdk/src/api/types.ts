import type {
  NormalizedApiSchema, NormalizedApiService, NormalizedApiSpecification,
  NormalizedEndpoint, NormalizedEndpointParameter, NormalizedGraphqlService,
} from "../findings/finding.types";

/**
 * API Security Engine domain types (Prompt 9). The engine's prime rule
 * (§"IMPORTANT"): this is NOT an unrestricted API attack engine — no
 * destructive mutations, no credential attacks, no mass-assignment or
 * authorization-bypass exploitation, no data modification. Everything here
 * models DISCOVERY, INVENTORY, INSPECTION and SAFE validation inside
 * explicitly authorized scope.
 */

export const API_TYPES = ["REST", "GRAPHQL", "WEBSOCKET", "UNKNOWN"] as const;
export type ApiType = (typeof API_TYPES)[number];

/** Authentication scheme kinds the platform understands as METADATA
 *  (§19). Values always travel as secret references — never in these
 *  records. */
export const API_AUTH_TYPES = ["NONE", "BASIC", "BEARER", "API_KEY", "COOKIE", "OAUTH2", "CUSTOM_HEADER"] as const;
export type ApiAuthType = (typeof API_AUTH_TYPES)[number];

export const SPEC_KINDS = ["OPENAPI", "SWAGGER", "POSTMAN_COLLECTION", "INSOMNIA_EXPORT", "GRAPHQL_SCHEMA"] as const;
export type SpecKind = (typeof SPEC_KINDS)[number];

/** One classified API operation — the unit the operation policy engine
 *  (§17) reasons about and schema-based testing filters by. */
export interface ApiOperation {
  method: string;
  /** Path TEMPLATE as declared (e.g. /users/{id}) — never a concrete URL
   *  with real object identifiers. */
  path: string;
  operationId?: string;
  /** Base URL this operation belongs to (from spec servers / discovery). */
  baseUrl?: string;
  hasRequestBody?: boolean;
  /** Declared authentication requirement from the source document. */
  authRequired?: boolean;
  authSchemes?: string[];
  contentTypes?: string[];
  source: string;
}

/**
 * The result of importing one specification document (§6/§8/§10/§12/§29):
 * inventory only. Imports NEVER produce findings — a schema is a map of
 * the surface, not evidence of a vulnerability (§51).
 */
export interface ApiImportResult {
  specification: NormalizedApiSpecification;
  apiServices: NormalizedApiService[];
  operations: ApiOperation[];
  /** Endpoint inventory rows (URLs are canonical base+path templates). */
  endpoints: NormalizedEndpoint[];
  parameters: NormalizedEndpointParameter[];
  /** Reusable schemas extracted once, referenced by endpoints (§36). */
  schemas: NormalizedApiSchema[];
  graphqlServices: NormalizedGraphqlService[];
  /** Security schemes declared by the document, as metadata (§19). */
  securitySchemes: { name: string; type: string; scheme?: string; in?: string }[];
  /** Non-fatal problems: external references NOT fetched (§7), skipped
   *  records, redacted secrets (§11). */
  warnings: string[];
  /** How many secret-looking values were dropped/redacted (§11) — the
   *  values themselves are never in this result. */
  secretsRedacted: number;
  metrics: Record<string, number>;
}

/** Authentication context for API testing (§20/§21): references only.
 *  `role` prepares the multi-identity architecture — identities are
 *  platform-provided TEST accounts, and cross-account object access is
 *  NOT performed in this phase (§21/§42). */
export const API_AUTH_ROLES = ["ANONYMOUS", "USER_A", "USER_B", "ADMIN_TEST"] as const;
export type ApiAuthRole = (typeof API_AUTH_ROLES)[number];

export interface ApiAuthContextRecord {
  id: string;
  workspaceId: string;
  apiServiceId?: string;
  role: ApiAuthRole;
  /** References into the Phase 8 profile architecture — never values. */
  authenticationProfileId?: string;
  sessionProfileId?: string;
  credentialReference?: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

/** Authorization test case ARCHITECTURE (§42): the record shape for a
 *  future, separately-approved authorization test. In this phase these
 *  records are design artifacts — `approvalStatus` starts NOT_APPROVED
 *  and NOTHING executes them: no cross-account object access, no
 *  enumeration of other users' objects (§42/§79). */
export interface AuthorizationTestCaseRecord {
  id: string;
  workspaceId: string;
  endpointId?: string;
  /** Object identifier TEMPLATE (e.g. {userId}) — never a real user's id. */
  objectIdentifier?: string;
  identityAContextId?: string;
  identityBContextId?: string;
  expectedAccess?: string;
  observedAccess?: string;
  approvalStatus: "NOT_APPROVED" | "APPROVED" | "REJECTED";
  createdBy: string;
  createdAt: string;
}

/** Safe test-data profile (§18): values an authorized admin provides for
 *  future schema testing. The platform never invents production-like
 *  data and never defaults to real customer data. */
export interface TestDataProfileRecord {
  id: string;
  workspaceId: string;
  name: string;
  description?: string;
  /** field name → safe test value supplied by an admin. */
  values: Record<string, string>;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}
