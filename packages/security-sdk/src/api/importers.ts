import { createHash } from "node:crypto";
import type {
  NormalizedApiSchema, NormalizedEndpointParameter, NormalizedGraphqlService,
} from "../findings/finding.types";
import { parseSpecDocument, resolveLocalRef, sanitizeSpecText, SpecImportError } from "./import-security";
import type { ApiImportResult } from "./types";

/**
 * Specification importers (Prompt 9 §8/§10/§12/§29). Every importer
 * treats its document as hostile (§7 — see import-security.ts), extracts
 * INVENTORY ONLY, and preserves provenance. Importers never produce
 * findings and never fetch anything: a URL inside a document is data,
 * not an instruction (§46).
 */

export interface ImportOptions {
  /** Provenance label recorded on every extracted record (§5). */
  source: string;
  /** Base URL used to resolve relative server URLs (the verified
   *  target's base) — supplied by the caller from trusted state. */
  fallbackBaseUrl?: string;
  /** Hard operation ceiling (§66): defaults to the admin cap. */
  maxOperations?: number;
}

const HARD_MAX_OPERATIONS = 5_000;
const MAX_SCHEMAS = 1_000;
const HTTP_METHODS = ["get", "put", "post", "delete", "patch", "head", "options", "trace"];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
function checksumOf(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

const SECRET_KEY_RE = /(token|secret|password|passwd|api[-_]?key|auth|credential|private|session|cookie|bearer)/i;
export function isSecretLikeKey(key: string): boolean {
  return SECRET_KEY_RE.test(key);
}

/** Join a base URL and a path TEMPLATE without mangling `{param}`
 *  placeholders (URL canonicalization would percent-encode them). The
 *  result is an inventory key, never a request target. */
export function joinTemplateUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

function originAndBase(baseUrl: string): { origin: string; host: string } {
  try {
    const u = new URL(baseUrl);
    return { origin: `${u.protocol}//${u.host}`, host: u.hostname.toLowerCase() };
  } catch {
    return { origin: "", host: "" };
  }
}

function authTypeFromScheme(scheme: Record<string, unknown>): string {
  const type = str(scheme.type)?.toLowerCase();
  const sch = str(scheme.scheme)?.toLowerCase();
  if (type === "http" && sch === "basic") return "BASIC";
  if (type === "http" && sch === "bearer") return "BEARER";
  if (type === "http") return "CUSTOM_HEADER";
  if (type === "apikey") return "API_KEY";
  if (type === "oauth2" || type === "openidconnect") return "OAUTH2";
  if (type === "mutualtls") return "CUSTOM_HEADER";
  return "CUSTOM_HEADER";
}

/** Flatten a JSON-schema object's property paths (BODY parameters, §35):
 *  `user.email`, `profile.name` — NAMES and structure only, never values.
 *  Depth and count are bounded; $refs resolve LOCALLY or not at all. */
export function schemaPropertyPaths(
  doc: Record<string, unknown>, schema: unknown, prefix = "", depth = 0, out: string[] = [],
): string[] {
  if (out.length >= 200 || depth > 4) return out;
  let s = schema;
  if (isRecord(s) && typeof s.$ref === "string") s = resolveLocalRef(doc, s.$ref);
  if (!isRecord(s)) return out;
  const props = isRecord(s.properties) ? s.properties : undefined;
  if (props) {
    for (const [name, sub] of Object.entries(props)) {
      const path = prefix ? `${prefix}.${name}` : name;
      out.push(path);
      schemaPropertyPaths(doc, sub, path, depth + 1, out);
      if (out.length >= 200) break;
    }
  }
  if (isRecord(s.items)) schemaPropertyPaths(doc, s.items, prefix, depth + 1, out);
  return out;
}

function schemaSummary(doc: Record<string, unknown>, name: string, schema: unknown, source: string): NormalizedApiSchema | undefined {
  let s = schema;
  if (isRecord(s) && typeof s.$ref === "string") s = resolveLocalRef(doc, s.$ref);
  if (!isRecord(s)) return undefined;
  const properties: Record<string, string> = {};
  if (isRecord(s.properties)) {
    for (const [propName, propSchema] of Object.entries(s.properties).slice(0, 100)) {
      const ps = isRecord(propSchema) ? propSchema : {};
      const type = str(ps.type) ?? (typeof ps.$ref === "string" ? "object(ref)" : "unknown");
      const format = str(ps.format);
      properties[propName] = format ? `${type}(${format})` : type;
    }
  }
  return {
    name,
    schemaType: str(s.type) ?? (s.properties ? "object" : "unknown"),
    requiredFields: Array.isArray(s.required) ? s.required.filter((r): r is string => typeof r === "string").slice(0, 100) : [],
    properties,
    source,
  };
}

function emptyResult(kind: ApiImportResult["specification"]["kind"], content: string, source: string, format: string): ApiImportResult {
  return {
    specification: {
      kind, source, checksum: checksumOf(content), parsedStatus: "PARSED",
      artifactRef: `api-specs/${checksumOf(content)}`,
    },
    apiServices: [], operations: [], endpoints: [], parameters: [], schemas: [], graphqlServices: [],
    securitySchemes: [], warnings: [`document format: ${format}`], secretsRedacted: 0, metrics: {},
  };
}

function guardOperationCount(count: number, opts: ImportOptions): void {
  const cap = Math.min(opts.maxOperations ?? HARD_MAX_OPERATIONS, HARD_MAX_OPERATIONS);
  if (count > cap) throw new SpecImportError(`document declares ${count} operations, exceeding the import limit of ${cap} (§66)`);
}

// ------------------------------- OpenAPI / Swagger (§8) -------------------------------

export class OpenApiImporter {
  parse(content: string, opts: ImportOptions): ApiImportResult {
    const parsed = parseSpecDocument(content);
    const doc = parsed.document;
    const isOpenApi = typeof doc.openapi === "string" && (doc.openapi as string).startsWith("3.");
    const isSwagger = doc.swagger === "2.0";
    if (!isOpenApi && !isSwagger) {
      throw new SpecImportError("document is neither OpenAPI 3.x nor Swagger 2.0 (no recognizable openapi/swagger version field)");
    }
    const kind = isOpenApi ? "OPENAPI" : "SWAGGER";
    const result = emptyResult(kind, content, opts.source, parsed.format);
    result.warnings.push(...parsed.warnings);
    result.specification.version = sanitizeSpecText(isRecord(doc.info) ? doc.info.version : undefined, 64);

    // Servers (§8): declared URLs are DATA — the caller scope-checks
    // them; the importer never fetches them.
    const declaredServers: string[] = [];
    if (isOpenApi && Array.isArray(doc.servers)) {
      for (const s of doc.servers) if (isRecord(s) && str(s.url)) declaredServers.push(s.url as string);
    }
    if (isSwagger) {
      const host = str(doc.host);
      const basePath = str(doc.basePath) ?? "";
      const schemes = Array.isArray(doc.schemes) && doc.schemes.length > 0 ? doc.schemes : ["https"];
      if (host) for (const scheme of schemes) declaredServers.push(`${scheme}://${host}${basePath}`);
    }
    if (declaredServers.length === 0 && opts.fallbackBaseUrl) declaredServers.push(opts.fallbackBaseUrl);
    const resolveServer = (raw: string): string => {
      if (/^https?:\/\//i.test(raw)) return raw.replace(/\/+$/, "");
      if (opts.fallbackBaseUrl) return joinTemplateUrl(opts.fallbackBaseUrl, raw);
      return raw.replace(/\/+$/, "");
    };
    const servers = declaredServers.map(resolveServer);
    const primaryBase = servers[0] ?? opts.fallbackBaseUrl ?? "";

    // Security schemes (§8/§19).
    const schemesRaw = isOpenApi && isRecord(doc.components) && isRecord(doc.components.securitySchemes)
      ? doc.components.securitySchemes
      : isRecord(doc.securityDefinitions) ? doc.securityDefinitions : {};
    for (const [name, scheme] of Object.entries(schemesRaw)) {
      if (!isRecord(scheme)) continue;
      result.securitySchemes.push({ name, type: str(scheme.type) ?? "unknown", ...(str(scheme.scheme) ? { scheme: str(scheme.scheme) } : {}), ...(str(scheme.in) ? { in: str(scheme.in) } : {}) });
    }
    const dominantAuth = result.securitySchemes.length > 0 ? authTypeFromScheme(schemesRaw[result.securitySchemes[0]!.name] as Record<string, unknown>) : undefined;
    const globalSecurity = Array.isArray(doc.security) ? doc.security : undefined;

    for (const baseUrl of servers) {
      const { host } = originAndBase(baseUrl);
      result.apiServices.push({
        baseUrl, host, apiType: "REST", source: opts.source,
        ...(result.specification.version ? { version: result.specification.version } : {}),
        ...(dominantAuth ? { authenticationType: dominantAuth } : { authenticationType: "NONE" }),
      });
    }

    // Component schemas (§36): stored once, referenced by endpoints.
    const components = isOpenApi && isRecord(doc.components) && isRecord(doc.components.schemas) ? doc.components.schemas
      : isRecord(doc.definitions) ? doc.definitions : {};
    for (const [name, schema] of Object.entries(components)) {
      if (result.schemas.length >= MAX_SCHEMAS) { result.warnings.push(`schema count capped at ${MAX_SCHEMAS}`); break; }
      const summary = schemaSummary(doc, name, schema, opts.source);
      if (summary) result.schemas.push(summary);
    }

    // Paths + operations (§8).
    const paths = isRecord(doc.paths) ? doc.paths : {};
    let opCount = 0;
    for (const [path, pathItem] of Object.entries(paths)) {
      if (!isRecord(pathItem)) continue;
      const pathParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];
      for (const method of HTTP_METHODS) {
        const operation = pathItem[method];
        if (!isRecord(operation)) continue;
        opCount++;
        guardOperationCount(opCount, opts);
        const operationId = sanitizeSpecText(operation.operationId, 128);
        const opParams = [...pathParams, ...(Array.isArray(operation.parameters) ? operation.parameters : [])];
        const endpointUrl = primaryBase ? joinTemplateUrl(primaryBase, path) : path;
        const paramRecords: NormalizedEndpointParameter[] = [];
        const paramNames: string[] = [];
        for (const rawParam of opParams) {
          const param = isRecord(rawParam) && typeof rawParam.$ref === "string" ? resolveLocalRef(doc, rawParam.$ref) : rawParam;
          if (!isRecord(param) || !str(param.name)) continue;
          const locationRaw = str(param.in)?.toLowerCase() ?? "query";
          const location = locationRaw === "path" ? "PATH" : locationRaw === "header" ? "HEADER" : locationRaw === "cookie" ? "COOKIE" : locationRaw === "body" || locationRaw === "formdata" ? "BODY" : "QUERY";
          paramRecords.push({ endpointUrl, name: param.name as string, location, sources: [opts.source], confidence: 1 });
          paramNames.push(param.name as string);
        }
        // Request body (§35): schema property paths as BODY parameters.
        let requestSchemaName: string | undefined;
        const requestBody = isRecord(operation.requestBody) ? operation.requestBody : undefined;
        const bodySchemaHolder = requestBody && isRecord(requestBody.content)
          ? Object.values(requestBody.content).find((c) => isRecord(c) && isRecord((c as Record<string, unknown>).schema))
          : method === "post" || method === "put" || method === "patch" ? undefined : undefined;
        const legacyBodyParam = opParams.find((p) => isRecord(p) && p.in === "body");
        const bodySchema = bodySchemaHolder ? (bodySchemaHolder as Record<string, unknown>).schema
          : isRecord(legacyBodyParam) ? legacyBodyParam.schema : undefined;
        if (bodySchema !== undefined) {
          requestSchemaName = `${operationId ?? `${method.toUpperCase()} ${path}`} requestBody`;
          const summary = schemaSummary(doc, requestSchemaName, bodySchema, opts.source);
          if (summary && result.schemas.length < MAX_SCHEMAS) result.schemas.push(summary);
          for (const pathName of schemaPropertyPaths(doc, bodySchema)) {
            paramRecords.push({ endpointUrl, name: pathName, location: "BODY", sources: [opts.source], confidence: 0.9 });
            paramNames.push(pathName);
          }
        }
        const contentTypes: string[] = [];
        if (requestBody && isRecord(requestBody.content)) contentTypes.push(...Object.keys(requestBody.content));
        if (isRecord(operation.responses)) {
          const first = Object.values(operation.responses).find((r) => isRecord(r) && isRecord((r as Record<string, unknown>).content)) as Record<string, unknown> | undefined;
          if (first && isRecord(first.content)) contentTypes.push(...Object.keys(first.content));
        }
        const opSecurity = Array.isArray(operation.security) ? operation.security : globalSecurity;
        const authSchemes = opSecurity ? [...new Set(opSecurity.flatMap((s) => (isRecord(s) ? Object.keys(s) : [])))] : [];
        const authRequired = opSecurity !== undefined && opSecurity.length > 0 && !opSecurity.some((s) => isRecord(s) && Object.keys(s).length === 0);
        result.operations.push({
          method: method.toUpperCase(), path, source: opts.source,
          ...(operationId ? { operationId } : {}),
          ...(primaryBase ? { baseUrl: primaryBase } : {}),
          hasRequestBody: bodySchema !== undefined,
          authRequired, authSchemes,
          ...(contentTypes.length > 0 ? { contentTypes: [...new Set(contentTypes)] } : {}),
        });
        result.parameters.push(...paramRecords);
        result.endpoints.push({
          url: endpointUrl, method: method.toUpperCase(), source: opts.source, sources: [opts.source],
          parameterNames: [...new Set(paramNames)].sort(),
          endpointType: "API",
          scopeStatus: "IN_SCOPE",
        });
        void requestSchemaName;
      }
    }
    result.specification.operationCount = opCount;
    result.metrics = {
      operations: opCount, endpoints: result.endpoints.length, parameters: result.parameters.length,
      schemas: result.schemas.length, servers: servers.length, externalRefs: parsed.externalRefs.length,
    };
    if (opCount > 500) result.warnings.push(`${opCount} operations exceeds the baseline schema-operation budget (500) — imported fully; scan-stage budgets still apply (§61)`);
    return result;
  }
}

// ------------------------------- Postman (§10/§11) -------------------------------

/** Postman environment variables (§11): names + secret classification
 *  ONLY. Secret values are counted and dropped — never returned. */
export function parsePostmanEnvironment(content: string): { name?: string; variables: { key: string; secret: boolean }[]; secretsRedacted: number } {
  const parsed = parseSpecDocument(content);
  const doc = parsed.document;
  const values = Array.isArray(doc.values) ? doc.values : [];
  const variables: { key: string; secret: boolean }[] = [];
  let secretsRedacted = 0;
  for (const v of values) {
    if (!isRecord(v) || !str(v.key)) continue;
    const secret = v.type === "secret" || isSecretLikeKey(v.key as string);
    if (secret) secretsRedacted++;
    variables.push({ key: v.key as string, secret });
  }
  return { ...(str(doc.name) ? { name: str(doc.name) } : {}), variables, secretsRedacted };
}

export class PostmanCollectionImporter {
  parse(content: string, opts: ImportOptions): ApiImportResult {
    const parsed = parseSpecDocument(content);
    const doc = parsed.document;
    const info = isRecord(doc.info) ? doc.info : {};
    if (!str(info.schema) || !(info.schema as string).includes("collection")) {
      throw new SpecImportError("document is not a Postman collection (info.schema does not declare a collection schema)");
    }
    const result = emptyResult("POSTMAN_COLLECTION", content, opts.source, parsed.format);
    result.warnings.push(...parsed.warnings);

    // Collection variables (§11): normal values may substitute {{vars}};
    // secret variables are dropped + counted, NEVER substituted or kept.
    const substitutions = new Map<string, string>();
    if (Array.isArray(doc.variable)) {
      for (const v of doc.variable) {
        if (!isRecord(v) || !str(v.key)) continue;
        if (isSecretLikeKey(v.key as string)) { result.secretsRedacted++; continue; }
        if (typeof v.value === "string" && v.value.length <= 256) substitutions.set(v.key as string, v.value);
      }
    }
    const substitute = (raw: string): string => raw.replace(/\{\{\s*([^}\s]+)\s*\}\}/g, (_m, name: string) => substitutions.get(name) ?? `{${name}}`);

    const collectionAuth = isRecord(doc.auth) ? str(doc.auth.type) : undefined;
    let firstBase = "";
    const walk = (items: unknown[]): void => {
      for (const item of items) {
        if (!isRecord(item)) continue;
        if (Array.isArray(item.item)) { walk(item.item); continue; }
        const request = isRecord(item.request) ? item.request : undefined;
        if (!request) continue;
        const method = (str(request.method) ?? "GET").toUpperCase();
        // URL: string form, or structured { host, path } form.
        let rawUrl = "";
        if (typeof request.url === "string") rawUrl = request.url;
        else if (isRecord(request.url)) {
          rawUrl = str(request.url.raw) ?? "";
          if (!rawUrl) {
            const host = Array.isArray(request.url.host) ? request.url.host.join(".") : "";
            const path = Array.isArray(request.url.path) ? request.url.path.join("/") : "";
            const protocol = str(request.url.protocol) ?? "https";
            if (host) rawUrl = `${protocol}://${host}/${path}`;
          }
        }
        if (!rawUrl) continue;
        const url = substitute(rawUrl);
        const noQuery = url.split("?")[0]!;
        const templateUrl = noQuery.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
        const { origin, host } = originAndBase(templateUrl);
        if (!firstBase && origin) firstBase = origin;
        const auth = isRecord(request.auth) ? str(request.auth.type) : collectionAuth;
        const authRequired = !!auth && auth !== "noauth";
        const paramRecords: NormalizedEndpointParameter[] = [];
        const paramNames: string[] = [];
        // Query parameters from the URL string (names only — values are
        // example data and are dropped).
        const qIndex = url.indexOf("?");
        if (qIndex >= 0) {
          for (const pair of url.slice(qIndex + 1).split("&")) {
            const name = pair.split("=")[0];
            if (name && !name.includes("{")) { paramRecords.push({ endpointUrl: templateUrl, name, location: "QUERY", sources: [opts.source], confidence: 0.9 }); paramNames.push(name); }
          }
        }
        if (isRecord(request.url) && Array.isArray(request.url.query)) {
          for (const q of request.url.query) {
            if (isRecord(q) && str(q.key) && q.disabled !== true) {
              paramRecords.push({ endpointUrl: templateUrl, name: q.key as string, location: "QUERY", sources: [opts.source], confidence: 1 });
              paramNames.push(q.key as string);
            }
          }
        }
        // Header NAMES only (§10 headers metadata) — values never kept.
        if (Array.isArray(request.header)) {
          for (const h of request.header) {
            const name = isRecord(h) ? str(h.key) : typeof h === "string" ? h.split(":")[0]?.trim() : undefined;
            if (name && h !== undefined && (isRecord(h) ? h.disabled !== true : true)) {
              paramRecords.push({ endpointUrl: templateUrl, name, location: "HEADER", sources: [opts.source], confidence: 0.8 });
            }
          }
        }
        // Body schema/example (§10): structure only. A JSON example's
        // property paths become BODY parameters; the example VALUES are
        // never stored.
        const body = isRecord(request.body) ? request.body : undefined;
        if (body) {
          if (typeof body.raw === "string" && body.raw.trim().startsWith("{")) {
            try {
              const example = JSON.parse(body.raw) as Record<string, unknown>;
              const paths = schemaPropertyPaths({}, exampleToSchema(example));
              for (const p of paths) { paramRecords.push({ endpointUrl: templateUrl, name: p, location: "BODY", sources: [opts.source], confidence: 0.7 }); paramNames.push(p); }
            } catch { result.warnings.push("a request body example did not parse as JSON — body structure skipped"); }
          }
          for (const listKey of ["urlencoded", "formdata"] as const) {
            if (Array.isArray(body[listKey])) {
              for (const field of body[listKey] as unknown[]) {
                if (isRecord(field) && str(field.key)) {
                  paramRecords.push({ endpointUrl: templateUrl, name: field.key as string, location: "BODY", sources: [opts.source], confidence: 1 });
                  paramNames.push(field.key as string);
                }
              }
            }
          }
        }
        void host;
        result.operations.push({
          method, path: templatePathOf(templateUrl), source: opts.source,
          ...(origin ? { baseUrl: origin } : {}),
          hasRequestBody: !!body, authRequired, authSchemes: authRequired && auth ? [auth] : [],
        });
        result.parameters.push(...paramRecords);
        result.endpoints.push({
          url: templateUrl, method, source: opts.source, sources: [opts.source],
          parameterNames: [...new Set(paramNames)].sort(), endpointType: "API", scopeStatus: "IN_SCOPE",
        });
      }
    };
    walk(Array.isArray(doc.item) ? doc.item : []);
    guardOperationCount(result.operations.length, opts);
    const base = firstBase || opts.fallbackBaseUrl || "";
    if (base) {
      const { host } = originAndBase(base);
      result.apiServices.push({
        baseUrl: base, host, apiType: "REST", source: opts.source,
        authenticationType: collectionAuth ? postmanAuthType(collectionAuth) : "NONE",
      });
    }
    if (result.secretsRedacted > 0) result.warnings.push(`${result.secretsRedacted} secret variable value(s) were dropped and replaced by secret references (§11)`);
    result.specification.operationCount = result.operations.length;
    result.metrics = { operations: result.operations.length, endpoints: result.endpoints.length, parameters: result.parameters.length, secretsRedacted: result.secretsRedacted };
    return result;
  }
}

function postmanAuthType(type: string): string {
  switch (type.toLowerCase()) {
    case "bearer": return "BEARER";
    case "basic": return "BASIC";
    case "apikey": return "API_KEY";
    case "oauth2": return "OAUTH2";
    default: return "CUSTOM_HEADER";
  }
}

/** Convert a JSON example VALUE into a structural schema (types only) so
 *  property-path extraction never touches the example's values. */
export function exampleToSchema(value: unknown): Record<string, unknown> {
  if (Array.isArray(value)) return { type: "array", items: value.length > 0 ? exampleToSchema(value[0]) : {} };
  if (isRecord(value)) {
    const properties: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) properties[k] = exampleToSchema(v);
    return { type: "object", properties };
  }
  return { type: typeof value };
}

function templatePathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    const idx = url.indexOf("/", url.indexOf("://") + 3);
    return idx >= 0 ? url.slice(idx) : url;
  }
}

// ------------------------------- Insomnia (§12) -------------------------------

export class InsomniaImporter {
  parse(content: string, opts: ImportOptions): ApiImportResult {
    const parsed = parseSpecDocument(content);
    const doc = parsed.document;
    if (doc._type !== "export" || !Array.isArray(doc.resources)) {
      throw new SpecImportError("document is not an Insomnia export (_type/resources missing)");
    }
    const result = emptyResult("INSOMNIA_EXPORT", content, opts.source, parsed.format);
    result.warnings.push(...parsed.warnings);
    const resources = doc.resources as unknown[];
    // Environments: variable NAMES classified; secret values dropped.
    const substitutions = new Map<string, string>();
    for (const r of resources) {
      if (!isRecord(r) || r._type !== "environment" || !isRecord(r.data)) continue;
      for (const [key, value] of Object.entries(r.data)) {
        if (isSecretLikeKey(key)) { result.secretsRedacted++; continue; }
        if (typeof value === "string" && value.length <= 256) substitutions.set(key, value);
      }
    }
    const substitute = (raw: string): string => raw
      .replace(/\{\{\s*_?\.\s*([A-Za-z0-9_]+)\s*\}\}/g, (_m, name: string) => substitutions.get(name) ?? `{${name}}`)
      .replace(/\{%\s*[^%]*%\}/g, "{template}");
    let firstBase = "";
    for (const r of resources) {
      if (!isRecord(r) || r._type !== "request") continue;
      const method = (str(r.method) ?? "GET").toUpperCase();
      const rawUrl = str(r.url);
      if (!rawUrl) continue;
      const url = substitute(rawUrl);
      const templateUrl = url.split("?")[0]!.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
      const { origin } = originAndBase(templateUrl);
      if (!firstBase && origin) firstBase = origin;
      const paramRecords: NormalizedEndpointParameter[] = [];
      const paramNames: string[] = [];
      if (Array.isArray(r.parameters)) {
        for (const p of r.parameters) {
          if (isRecord(p) && str(p.name) && p.disabled !== true) {
            paramRecords.push({ endpointUrl: templateUrl, name: p.name as string, location: "QUERY", sources: [opts.source], confidence: 1 });
            paramNames.push(p.name as string);
          }
        }
      }
      if (Array.isArray(r.headers)) {
        for (const h of r.headers) {
          if (isRecord(h) && str(h.name) && h.disabled !== true) {
            paramRecords.push({ endpointUrl: templateUrl, name: h.name as string, location: "HEADER", sources: [opts.source], confidence: 0.8 });
          }
        }
      }
      const body = isRecord(r.body) ? r.body : undefined;
      if (body && Array.isArray(body.params)) {
        for (const p of body.params) {
          if (isRecord(p) && str(p.name)) {
            paramRecords.push({ endpointUrl: templateUrl, name: p.name as string, location: "BODY", sources: [opts.source], confidence: 1 });
            paramNames.push(p.name as string);
          }
        }
      }
      if (body && typeof body.text === "string" && body.text.trim().startsWith("{")) {
        try {
          const example = JSON.parse(body.text) as Record<string, unknown>;
          for (const p of schemaPropertyPaths({}, exampleToSchema(example))) {
            paramRecords.push({ endpointUrl: templateUrl, name: p, location: "BODY", sources: [opts.source], confidence: 0.7 });
            paramNames.push(p);
          }
        } catch { result.warnings.push("a request body example did not parse as JSON — body structure skipped"); }
      }
      const auth = isRecord(r.authentication) ? str(r.authentication.type) : undefined;
      result.operations.push({
        method, path: templatePathOf(templateUrl), source: opts.source,
        ...(origin ? { baseUrl: origin } : {}),
        hasRequestBody: !!body, authRequired: !!auth, authSchemes: auth ? [auth] : [],
      });
      result.parameters.push(...paramRecords);
      result.endpoints.push({
        url: templateUrl, method, source: opts.source, sources: [opts.source],
        parameterNames: [...new Set(paramNames)].sort(), endpointType: "API", scopeStatus: "IN_SCOPE",
      });
    }
    guardOperationCount(result.operations.length, opts);
    const base = firstBase || opts.fallbackBaseUrl || "";
    if (base) {
      const { host } = originAndBase(base);
      result.apiServices.push({ baseUrl: base, host, apiType: "REST", source: opts.source, authenticationType: "NONE" });
    }
    if (result.secretsRedacted > 0) result.warnings.push(`${result.secretsRedacted} secret environment value(s) were dropped and replaced by secret references (§11/§12)`);
    result.specification.operationCount = result.operations.length;
    result.metrics = { operations: result.operations.length, endpoints: result.endpoints.length, parameters: result.parameters.length, secretsRedacted: result.secretsRedacted };
    return result;
  }
}

// ------------------------------- GraphQL introspection (§29) -------------------------------

export interface GraphqlInventory {
  service: NormalizedGraphqlService;
  /** Operation field names per kind — inventory, used by the GraphQL
   *  page (§57). Mutations are listed as NOT automatically tested. */
  operations: { queries: string[]; mutations: string[]; subscriptions: string[] };
  typeNames: string[];
  warnings: string[];
}

/** Parse a GraphQL introspection result into inventory (§29). Accepts
 *  the full response envelope ({ data: { __schema } }), a bare __schema,
 *  or an InQL-style schema dump wrapping the same structure. */
export function parseGraphqlIntrospection(raw: unknown, opts: { endpointUrl: string; source: string }): GraphqlInventory {
  const root = isRecord(raw) && isRecord(raw.data) ? raw.data : raw;
  const schema = isRecord(root) && isRecord((root as Record<string, unknown>).__schema) ? (root as Record<string, unknown>).__schema as Record<string, unknown> : undefined;
  if (!schema) throw new SpecImportError("document does not contain a GraphQL introspection __schema");
  const types = Array.isArray(schema.types) ? schema.types.filter(isRecord) : [];
  const byName = new Map<string, Record<string, unknown>>();
  for (const t of types) if (str(t.name)) byName.set(t.name as string, t);
  const fieldsOf = (typeName: unknown): string[] => {
    if (typeof typeName !== "string") return [];
    const t = byName.get(typeName);
    if (!t || !Array.isArray(t.fields)) return [];
    return t.fields.filter(isRecord).map((f) => str(f.name)).filter((n): n is string => !!n).slice(0, 500);
  };
  const queryType = isRecord(schema.queryType) ? str(schema.queryType.name) : undefined;
  const mutationType = isRecord(schema.mutationType) ? str(schema.mutationType.name) : undefined;
  const subscriptionType = isRecord(schema.subscriptionType) ? str(schema.subscriptionType.name) : undefined;
  const queries = fieldsOf(queryType);
  const mutations = fieldsOf(mutationType);
  const subscriptions = fieldsOf(subscriptionType);
  const visibleTypes = types.filter((t) => {
    const name = str(t.name) ?? "";
    return !name.startsWith("__");
  });
  const { host } = originAndBase(opts.endpointUrl);
  return {
    service: {
      endpointUrl: opts.endpointUrl, host, schemaAvailable: true,
      queries: queries.length, mutations: mutations.length, subscriptions: subscriptions.length,
      types: visibleTypes.length, source: opts.source, scopeStatus: "IN_SCOPE",
    },
    operations: { queries, mutations, subscriptions },
    typeNames: visibleTypes.map((t) => str(t.name)!).filter(Boolean).slice(0, 500),
    warnings: mutations.length > 0 ? [`${mutations.length} mutation(s) inventoried — mutations are NOT automatically tested (§30)`] : [],
  };
}

export class GraphqlSchemaImporter {
  parse(content: string, opts: ImportOptions & { endpointUrl: string }): ApiImportResult {
    const parsed = parseSpecDocument(content);
    const inventory = parseGraphqlIntrospection(parsed.document, { endpointUrl: opts.endpointUrl, source: opts.source });
    const result = emptyResult("GRAPHQL_SCHEMA", content, opts.source, parsed.format);
    result.warnings.push(...parsed.warnings, ...inventory.warnings);
    result.graphqlServices.push(inventory.service);
    result.apiServices.push({
      baseUrl: opts.endpointUrl, host: inventory.service.host, apiType: "GRAPHQL", source: opts.source,
      authenticationType: inventory.service.authenticationRequired ? "BEARER" : "NONE",
    });
    result.endpoints.push({
      url: opts.endpointUrl, method: "POST", source: opts.source, sources: [opts.source],
      parameterNames: [], endpointType: "API", scopeStatus: "IN_SCOPE",
    });
    const opCount = inventory.service.queries + inventory.service.mutations + inventory.service.subscriptions;
    result.specification.operationCount = opCount;
    result.metrics = {
      graphqlOperations: opCount, queries: inventory.service.queries, mutations: inventory.service.mutations,
      subscriptions: inventory.service.subscriptions, types: inventory.service.types,
    };
    return result;
  }
}
