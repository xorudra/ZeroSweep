import type { Capability } from "../adapter/adapter.types";

/**
 * Interactive proxy/scanner connector domain types (Prompt 8 §2–§3, §13–§19).
 *
 * Proxy products (OWASP ZAP, Burp Suite Professional, Caido) are long-lived
 * SERVICES, not CLI tools: they are reached through an administrator-
 * registered ScannerInstance whose actual network endpoint is resolved
 * inside the trusted backend from an opaque endpoint REFERENCE (§15–§17).
 * No scan request, API payload or queue message ever carries a scanner
 * host/port/URL, and no management secret is ever stored in plaintext —
 * instances carry credential REFERENCES only (§20), resolved by the worker
 * at execution time through a SecretResolver.
 */

export const SCANNER_PRODUCTS = ["ZAP", "BURP", "CAIDO"] as const;
export type ScannerProduct = (typeof SCANNER_PRODUCTS)[number];

/** Capabilities a connector product can EVER support (§4/§10/§13). What a
 *  given deployment actually offers is detected per instance (§14) — this
 *  list is the ceiling, never an assumption. */
export const PRODUCT_CAPABILITIES: Record<ScannerProduct, Capability[]> = {
  ZAP: ["PROXY", "PASSIVE_ANALYSIS", "CONTEXT_MANAGEMENT", "ENDPOINT_IMPORT", "ISSUE_IMPORT", "WEB_CRAWLING", "ENDPOINT_DISCOVERY", "VULNERABILITY_SCANNING", "ACTIVE_WEB_SCANNING"],
  BURP: ["PROXY", "PASSIVE_ANALYSIS", "SITE_MAP_IMPORT", "ISSUE_IMPORT", "WEB_CRAWLING", "ACTIVE_WEB_SCANNING"],
  CAIDO: ["PROXY", "TRAFFIC_ANALYSIS", "ENDPOINT_DISCOVERY", "REQUEST_COLLECTION", "ISSUE_IMPORT"],
};

export const PRODUCT_SLUGS: Record<ScannerProduct, string> = {
  ZAP: "owasp-zap",
  BURP: "burp-suite-professional",
  CAIDO: "caido",
};
export const SLUG_PRODUCTS: Record<string, ScannerProduct> = {
  "owasp-zap": "ZAP",
  "burp-suite-professional": "BURP",
  caido: "CAIDO",
};

/** How the scanner deployment is provided (§9/§55). IMPORT_ONLY instances
 *  never receive network traffic from DSRclone — they exist so imported
 *  exports are attributed to a registered, approved source. */
export type ScannerDeploymentType = "MANAGED_DAEMON" | "ADMIN_PROVIDED" | "IMPORT_ONLY";

/** Scanner health (§53 + §66): NOT_CONFIGURED is a first-class, honest
 *  state — an unconfigured commercial connector is NOT an error and must
 *  never be reported as a failure or a success. */
export const SCANNER_HEALTH_STATUSES = ["NOT_CONFIGURED", "HEALTHY", "DEGRADED", "UNAVAILABLE", "MISCONFIGURED"] as const;
export type ScannerHealthStatus = (typeof SCANNER_HEALTH_STATUSES)[number];

export interface ScannerHealth {
  status: ScannerHealthStatus;
  /** Product version when the deployment actually reported one. */
  version?: string;
  /** Capabilities detected for THIS deployment (§14) — declared ∩ supported,
   *  refined by probes; never assumed from the product brochure. */
  capabilities: Capability[];
  /** License state when the product reports it (e.g. Burp Professional). */
  licenseState?: string;
  latencyMs?: number;
  detail?: string;
  checkedAt: string;
}

/**
 * Scanner instance (§15) — administrator-registered (§16). `endpointReference`
 * is an OPAQUE reference (e.g. "ZAP_DAEMON_PRIMARY") that the trusted backend
 * resolves to a real endpoint from server-side configuration; it is never a
 * URL and never accepted from scan requests (§17). `credentialReference`
 * names a secret in the vault — the value is never stored here (§20).
 */
export interface ScannerInstanceRecord {
  id: string;
  organizationId: string;
  /** Null = available to the whole organization (admin-owned, §15). */
  workspaceId?: string;
  toolSlug: string;
  product: ScannerProduct;
  name: string;
  endpointReference: string;
  deploymentType: ScannerDeploymentType;
  /** Capabilities the administrator declares this deployment offers (§14). */
  declaredCapabilities: Capability[];
  credentialReference?: string;
  /** Reference to the server-side configuration entry (§15). */
  configurationReference?: string;
  enabled: boolean;
  healthStatus: ScannerHealthStatus;
  version?: string;
  detectedCapabilities: Capability[];
  licenseState?: string;
  lastHealthCheck?: string;
  lastLatencyMs?: number;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

/** Endpoint references are deliberately NOT URLs (§16/§17/§71): an admin
 *  registers a reference; the mapping reference → endpoint lives only in
 *  server-side configuration, so no API input can steer the backend toward
 *  an arbitrary internal address (SSRF through fake scanner endpoints). */
export const ENDPOINT_REFERENCE_PATTERN = /^[A-Z][A-Z0-9_:-]{2,63}$/;

export function validateEndpointReference(ref: unknown): { ok: true } | { ok: false; reason: string } {
  if (typeof ref !== "string" || ref.length === 0) return { ok: false, reason: "endpointReference is required" };
  if (/[:/]\/\//.test(ref) || ref.includes("/") || ref.includes("\\")) {
    return { ok: false, reason: "endpointReference must be an opaque reference, not a URL — scanner endpoints are resolved from trusted server configuration (§16/§17)" };
  }
  if (/\.\d{1,3}\.\d{1,3}/.test(ref) || /^\d+\.\d+\.\d+\.\d+$/.test(ref) || ref.includes("@")) {
    return { ok: false, reason: "endpointReference must not contain a host or address — scanner endpoints are resolved from trusted server configuration (§16/§17)" };
  }
  if (!ENDPOINT_REFERENCE_PATTERN.test(ref)) {
    return { ok: false, reason: "endpointReference must match [A-Z][A-Z0-9_:-]{2,63} (uppercase reference name)" };
  }
  return { ok: true };
}

/** Session profile (§18): METADATA about a test identity. Raw session
 *  tokens/cookies are never stored here — only the credential REFERENCE
 *  and policies expressed as header/cookie NAMES (§20). */
export type SessionProfileType = "ANONYMOUS" | "AUTHENTICATED" | "API_AUTHENTICATED";
export interface SessionProfileRecord {
  id: string;
  workspaceId: string;
  name: string;
  type: SessionProfileType;
  credentialReference?: string;
  /** Cookie NAMES the session may carry — never values. */
  cookiePolicy?: { allowedCookieNames: string[] };
  /** Header NAMES the session may add — values come from the secret. */
  headerPolicy?: { headerNames: string[] };
  /** Session validation probe (§22): a known authenticated URL + expected
   *  signal. A cookie existing is never treated as proof of validity. */
  validation?: { authenticatedUrl?: string; expectedStatus?: number; expectedMarker?: string };
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

/** Authentication profile (§19): architecture for future login modes.
 *  Configuration carries field/header NAMES and paths only — there is
 *  deliberately no support for arbitrary login scripts. */
export const AUTHENTICATION_MODES = ["FORM", "BASIC", "BEARER", "API_KEY", "COOKIE", "OAUTH", "CUSTOM_HEADER"] as const;
export type AuthenticationMode = (typeof AUTHENTICATION_MODES)[number];
export interface AuthenticationProfileRecord {
  id: string;
  workspaceId: string;
  name: string;
  mode: AuthenticationMode;
  credentialReference?: string;
  sessionProfileId?: string;
  /** Non-secret configuration: login path, form field NAMES, header NAME. */
  config?: { loginPath?: string; usernameField?: string; passwordField?: string; headerName?: string };
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

/** Isolated scanner context/session for ONE assessment (§6). Contexts are
 *  never shared across tenants: the connector refuses to reuse a context
 *  whose workspace/assessment binding differs from the request. */
export interface ScannerContextRecord {
  id: string;
  instanceId: string;
  product: ScannerProduct;
  workspaceId: string;
  assessmentId: string;
  scanId?: string;
  /** Vendor-side context name (opaque to users). */
  vendorContextName: string;
  includedTargets: string[];
  excludedTargets: string[];
  sessionProfileId?: string;
  status: "ACTIVE" | "DESTROYED";
  createdAt: string;
  destroyedAt?: string;
}

/** Resolves a secret REFERENCE to its value inside the trusted execution
 *  boundary (§20). Implementations read env/vault; the value is used for a
 *  single connector call and never logged, queued or returned. */
export interface SecretResolver {
  resolve(reference: string): Promise<string | undefined>;
}

/** Resolves an endpoint REFERENCE to the real endpoint from trusted
 *  server-side configuration (§15–§17). Undefined = not configured on this
 *  host, which makes the instance MISCONFIGURED, never "guessed". */
export interface EndpointResolver {
  resolve(reference: string): Promise<{ baseUrl: string; approvedInternal?: boolean } | undefined>;
}

/** Read access to registered scanner instances for connectors. Implemented
 *  by the API/worker over Prisma (production) or in-memory (tests). */
export interface ScannerInstanceProvider {
  listEnabled(product: ScannerProduct): Promise<ScannerInstanceRecord[]>;
  getById(id: string): Promise<ScannerInstanceRecord | null>;
  /** Synchronous snapshot for plan-time health (§39-style probing): plan
   *  building is synchronous, health is derived from the last snapshot. */
  snapshot(): ScannerInstanceRecord[];
}

/** In-memory provider (tests + API plan-time snapshots). */
export class InMemoryScannerInstanceProvider implements ScannerInstanceProvider {
  constructor(private readonly instances: ScannerInstanceRecord[] = []) {}
  add(instance: ScannerInstanceRecord): void { this.instances.push(instance); }
  async listEnabled(product: ScannerProduct): Promise<ScannerInstanceRecord[]> {
    return this.instances.filter((i) => i.product === product && i.enabled);
  }
  async getById(id: string): Promise<ScannerInstanceRecord | null> {
    return this.instances.find((i) => i.id === id) ?? null;
  }
  snapshot(): ScannerInstanceRecord[] { return [...this.instances]; }
}

/** Env-backed secret resolver: reference name → process env value. The
 *  reference IS the env var name (a name, never a value). */
export class EnvSecretResolver implements SecretResolver {
  async resolve(reference: string): Promise<string | undefined> {
    if (!/^[A-Z][A-Z0-9_]{2,127}$/.test(reference)) return undefined;
    const v = process.env[reference];
    return v && v.length > 0 ? v : undefined;
  }
}

/** Env-backed endpoint resolver: DSRCLONE_SCANNER_ENDPOINTS is a JSON map
 *  of reference → { baseUrl, approvedInternal } held ONLY in server
 *  configuration (§17). Malformed config resolves nothing. */
export class EnvEndpointResolver implements EndpointResolver {
  async resolve(reference: string): Promise<{ baseUrl: string; approvedInternal?: boolean } | undefined> {
    try {
      const raw = process.env.DSRCLONE_SCANNER_ENDPOINTS;
      if (!raw) return undefined;
      const map = JSON.parse(raw) as Record<string, { baseUrl?: string; approvedInternal?: boolean }>;
      const entry = map[reference];
      if (!entry?.baseUrl) return undefined;
      return { baseUrl: entry.baseUrl, ...(entry.approvedInternal ? { approvedInternal: true } : {}) };
    } catch {
      return undefined;
    }
  }
}

/** Read access to session profiles for connectors (worker resolves the
 *  profile record — metadata + credential reference — inside the trusted
 *  boundary; the secret itself is resolved separately, per call). */
export interface SessionProfileProvider {
  getById(id: string): Promise<SessionProfileRecord | null>;
}

export class InMemorySessionProfileProvider implements SessionProfileProvider {
  constructor(private readonly profiles: SessionProfileRecord[] = []) {}
  add(profile: SessionProfileRecord): void { this.profiles.push(profile); }
  async getById(id: string): Promise<SessionProfileRecord | null> {
    return this.profiles.find((p) => p.id === id) ?? null;
  }
}

/** Map-backed resolvers for tests (fixture environments). */
export class MapSecretResolver implements SecretResolver {
  constructor(private readonly values: Record<string, string>) {}
  async resolve(reference: string): Promise<string | undefined> { return this.values[reference]; }
}
export class MapEndpointResolver implements EndpointResolver {
  constructor(private readonly map: Record<string, { baseUrl: string; approvedInternal?: boolean }>) {}
  async resolve(reference: string): Promise<{ baseUrl: string; approvedInternal?: boolean } | undefined> {
    return this.map[reference];
  }
}
