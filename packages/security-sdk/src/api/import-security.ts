import { load as yamlLoad, JSON_SCHEMA as YAML_JSON_SCHEMA } from "js-yaml";
import { clampDiscoveryBudget, type DiscoveryBudget } from "../recon/budget";

/**
 * Specification import security (Prompt 9 §7/§66/§74). Imported
 * specifications are HOSTILE INPUT:
 *  - size is capped BEFORE parsing (parser resource exhaustion);
 *  - YAML is parsed with js-yaml's JSON_SCHEMA only — no custom tags, no
 *    `!!js/function`, no merge-key bombs; duplicate keys throw;
 *  - document complexity (depth / node count / string length) is capped;
 *  - external references ($ref to http/file/…) are COLLECTED and reported
 *    but NEVER fetched — no remote schema fetching, ever (§7/§46);
 *  - local references are counted and unresolved/circular reference
 *    graphs are bounded so recursive schemas cannot exhaust the parser.
 */

export class SpecImportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SpecImportError";
  }
}

export const SPEC_MAX_DEPTH = 32;
export const SPEC_MAX_NODES = 100_000;
export const SPEC_MAX_STRING = 16_384;
export const SPEC_MAX_REFERENCES = 5_000;

export interface ParsedSpecDocument {
  document: Record<string, unknown>;
  format: "JSON" | "YAML";
  /** External reference targets found in the document — recorded, never
   *  dereferenced (§7). */
  externalRefs: string[];
  /** Total $ref count (local + external), bounded by SPEC_MAX_REFERENCES. */
  referenceCount: number;
  warnings: string[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Structural walk enforcing §66 complexity limits and collecting refs. */
function walkAndGuard(node: unknown, depth: number, state: { nodes: number; refs: number; external: string[] }): void {
  if (depth > SPEC_MAX_DEPTH) throw new SpecImportError(`document exceeds the maximum nesting depth (${SPEC_MAX_DEPTH})`);
  state.nodes++;
  if (state.nodes > SPEC_MAX_NODES) throw new SpecImportError(`document exceeds the maximum node count (${SPEC_MAX_NODES})`);
  if (typeof node === "string") {
    if (node.length > SPEC_MAX_STRING) throw new SpecImportError(`document contains a string longer than ${SPEC_MAX_STRING} characters`);
    return;
  }
  if (Array.isArray(node)) {
    for (const item of node) walkAndGuard(item, depth + 1, state);
    return;
  }
  if (isRecord(node)) {
    for (const [key, value] of Object.entries(node)) {
      if (key === "$ref" && typeof value === "string") {
        state.refs++;
        if (state.refs > SPEC_MAX_REFERENCES) throw new SpecImportError(`document exceeds the maximum reference count (${SPEC_MAX_REFERENCES})`);
        if (!value.startsWith("#")) state.external.push(value);
      }
      walkAndGuard(value, depth + 1, state);
    }
  }
}

/**
 * Parse a specification document (JSON or YAML) under the §7 guards.
 * `maxBytes` defaults to the platform budget's maxSpecSize (admin-capped
 * via clampDiscoveryBudget). Throws SpecImportError on ANY violation —
 * hostile documents are rejected, never partially trusted.
 */
export function parseSpecDocument(content: string, opts: { maxBytes?: number } = {}): ParsedSpecDocument {
  if (typeof content !== "string" || content.trim().length === 0) {
    throw new SpecImportError("specification document is empty");
  }
  const budget: DiscoveryBudget = clampDiscoveryBudget({ maxSpecSize: opts.maxBytes });
  const maxBytes = Math.min(opts.maxBytes ?? budget.maxSpecSize, budget.maxSpecSize);
  const bytes = Buffer.byteLength(content, "utf8");
  if (bytes > maxBytes) {
    throw new SpecImportError(`specification document is ${bytes} bytes, exceeding the import limit of ${maxBytes} bytes (§7/§66)`);
  }

  let document: unknown;
  let format: "JSON" | "YAML" = "JSON";
  const trimmed = content.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      document = JSON.parse(trimmed);
    } catch {
      throw new SpecImportError("document looks like JSON but does not parse — malformed documents are rejected (§74)");
    }
  } else {
    format = "YAML";
    try {
      // JSON_SCHEMA: core scalar types only. Custom tags (including
      // !!js/function and friends) are unknown-tag errors under this
      // schema, and duplicate mapping keys throw — unsafe YAML features
      // are rejected, not interpreted (§7).
      document = yamlLoad(content, { schema: YAML_JSON_SCHEMA });
    } catch (err) {
      throw new SpecImportError(`YAML document rejected: ${err instanceof Error ? err.message.split("\n")[0] : "parse failure"}`);
    }
  }
  if (!isRecord(document)) throw new SpecImportError("specification document must be a JSON/YAML object at the top level");

  const state = { nodes: 0, refs: 0, external: [] as string[] };
  walkAndGuard(document, 0, state);
  const warnings: string[] = [];
  if (state.external.length > 0) {
    warnings.push(`${state.external.length} external reference(s) were NOT fetched (remote schema fetching is disabled, §7): ${state.external.slice(0, 5).join(", ")}${state.external.length > 5 ? ", …" : ""}`);
  }
  return { document, format, externalRefs: state.external, referenceCount: state.refs, warnings };
}

/** Resolve a LOCAL JSON pointer (#/components/schemas/Pet) inside the
 *  same document. External pointers never resolve (§7); pointer depth
 *  and hop count are bounded so recursive schemas terminate (§66). */
export function resolveLocalRef(document: Record<string, unknown>, ref: string, maxHops = 8): unknown {
  let current: unknown = document;
  let hops = 0;
  const seen = new Set<string>();
  let pointer = ref;
  while (pointer.startsWith("#/")) {
    if (seen.has(pointer) || hops++ > maxHops) return undefined; // circular or too deep — unresolved, not fatal
    seen.add(pointer);
    const segments = pointer.slice(2).split("/").map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
    current = document;
    for (const seg of segments) {
      if (!isRecord(current) && !Array.isArray(current)) return undefined;
      current = (current as Record<string, unknown>)[seg];
      if (current === undefined) return undefined;
    }
    if (isRecord(current) && typeof current.$ref === "string" && (current.$ref as string).startsWith("#/")) {
      pointer = current.$ref as string;
      continue;
    }
    return current;
  }
  return undefined;
}

/** A document string that is safe to keep as inventory metadata:
 *  control characters stripped, length capped. Rendering layers still
 *  escape — stored data is never trusted as markup (§7 stored XSS). */
export function sanitizeSpecText(value: unknown, max = 500): string | undefined {
  if (typeof value !== "string") return undefined;
  // eslint-disable-next-line no-control-regex -- stripping control chars IS the sanitization
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return cleaned.length === 0 ? undefined : cleaned.slice(0, max);
}

/** §9: the conservative, well-known API documentation locations the web
 *  inventory may flag as specification CANDIDATES. Detection records a
 *  candidate only — retrieval happens through the guarded import path,
 *  in scope and policy permitting; there is no brute-force list. */
export const SPEC_CANDIDATE_PATHS = [
  "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
  "/api/openapi.json", "/api/swagger.json", "/api-docs", "/swagger-ui",
  "/swagger-ui.html", "/v3/api-docs", "/v2/api-docs", "/redoc",
] as const;

export function isSpecCandidatePath(url: string): boolean {
  try {
    const u = new URL(url);
    const path = u.pathname.toLowerCase();
    return (SPEC_CANDIDATE_PATHS as readonly string[]).some((p) => path === p || path.endsWith(p));
  } catch {
    return false;
  }
}
