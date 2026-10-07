/**
 * Prompt 14 — hostile-input guards for cloud data (§90–§102).
 *
 * Everything a cloud provider returns is untrusted input: API
 * responses, IAM policy documents, tags/labels and tool reports can be
 * oversized, deeply nested, or carry script strings, terminal escapes
 * and forged metadata (§99). Parsers bound size/depth BEFORE walking;
 * identity fields are validated, display fields sanitized (§99), and
 * endpoints pass the SSRF policy (§101) before any connector use.
 */
import { blockedTargetReason } from "../scope/scope.matcher";
import { sanitizeCloudText, sanitizeStringMap } from "../cloudnative/sanitize";

export { sanitizeCloudText, sanitizeStringMap };

export const MAX_CLOUD_PAYLOAD_BYTES = 10 * 1024 * 1024; // 10 MiB per provider response / report
export const MAX_CLOUD_JSON_DEPTH = 32;
export const MAX_IAM_POLICY_BYTES = 256 * 1024;
export const MAX_IAM_STATEMENTS = 100;
export const MAX_IAM_ACTIONS = 512;

function jsonDepth(value: unknown, depth = 0): number {
  if (depth > MAX_CLOUD_JSON_DEPTH) return depth;
  if (Array.isArray(value)) return value.length === 0 ? depth : Math.max(...value.map((v) => jsonDepth(v, depth + 1)));
  if (value && typeof value === "object") {
    const entries = Object.values(value as Record<string, unknown>);
    return entries.length === 0 ? depth : Math.max(...entries.map((v) => jsonDepth(v, depth + 1)));
  }
  return depth;
}

/** Parse a JSON payload with hard size + depth bounds (§99). Throws on
 *  oversize, malformed or over-nested input — callers surface that as a
 *  rejected report, never a partial silent parse. */
export function parseBoundedJson(text: string, opts: { maxBytes?: number; what?: string } = {}): unknown {
  const maxBytes = opts.maxBytes ?? MAX_CLOUD_PAYLOAD_BYTES;
  if (typeof text !== "string" || text.length === 0) throw new Error(`${opts.what ?? "payload"}: empty`);
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new Error(`${opts.what ?? "payload"}: exceeds ${maxBytes} bytes`);
  const parsed = JSON.parse(text) as unknown;
  if (jsonDepth(parsed) > MAX_CLOUD_JSON_DEPTH) throw new Error(`${opts.what ?? "payload"}: nesting exceeds ${MAX_CLOUD_JSON_DEPTH}`);
  return parsed;
}

export function cloudRec(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
export function cloudArr(v: unknown): Record<string, unknown>[] {
  return Array.isArray(v) ? v.filter((x): x is Record<string, unknown> => !!x && typeof x === "object") : [];
}
export function cloudStr(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
export function cloudBool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}
export function cloudNum(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/** SSRF guard for cloud/Steampipe/registry endpoints (§101): HTTPS
 *  only, no embedded credentials, and the host must not resolve into
 *  blocked infrastructure (loopback / private / link-local / cloud
 *  metadata ranges) unless an explicitly approved internal engagement
 *  allows it. Expected verdict for malicious endpoints: DENIED. */
export function cloudEndpointVerdict(rawUrl: string, opts: { approvedInternal?: boolean } = {}): { allowed: boolean; reason?: string } {
  let url: URL;
  try { url = new URL(rawUrl); } catch { return { allowed: false, reason: "ENDPOINT_URL_INVALID" }; }
  if (url.protocol !== "https:") return { allowed: false, reason: "ENDPOINT_NOT_HTTPS" };
  if (url.username || url.password) return { allowed: false, reason: "ENDPOINT_EMBEDDED_CREDENTIALS" };
  const blocked = blockedTargetReason(url.hostname.toLowerCase());
  if (blocked && !opts.approvedInternal) return { allowed: false, reason: `ENDPOINT_BLOCKED:${blocked}` };
  return { allowed: true };
}

/** One parsed IAM policy statement, reduced to the facts the IAM
 *  engine reasons over (§36/§38/§42). Policy documents are untrusted:
 *  parsed under byte/statement/action caps, never evaluated as code. */
export interface IamPolicyStatement {
  effect: "Allow" | "Deny" | "Unknown";
  actions: string[];
  resources: string[];
  hasCondition: boolean;
}

export interface ParsedIamPolicy {
  statements: IamPolicyStatement[];
  /** Actions granted on "*" (or service-wide wildcards) with Allow. */
  wildcardActions: string[];
  /** True when the policy grants full administrative access ("*" on "*"). */
  isAdministratorEquivalent: boolean;
  /** Principals a trust policy grants assumption to (§42). */
  trustedPrincipals: string[];
}

function toStringList(v: unknown): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string").slice(0, MAX_IAM_ACTIONS);
  return [];
}

/** Parse an AWS-style IAM policy document (also the shape Azure/GCP
 *  exports are normalized into before analysis). Bounded and total:
 *  malformed input yields an empty parse, never an exception. */
export function parseIamPolicyDocument(raw: unknown): ParsedIamPolicy {
  const empty: ParsedIamPolicy = { statements: [], wildcardActions: [], isAdministratorEquivalent: false, trustedPrincipals: [] };
  let doc: unknown = raw;
  if (typeof raw === "string") {
    if (Buffer.byteLength(raw, "utf8") > MAX_IAM_POLICY_BYTES) return empty;
    try { doc = JSON.parse(raw) as unknown; } catch { return empty; }
  }
  const root = cloudRec(doc);
  const rawStatements = Array.isArray(root.Statement) ? root.Statement : root.Statement ? [root.Statement] : [];
  const statements: IamPolicyStatement[] = [];
  const wildcardActions = new Set<string>();
  const trustedPrincipals = new Set<string>();
  let admin = false;
  for (const s of rawStatements.slice(0, MAX_IAM_STATEMENTS)) {
    const stmt = cloudRec(s);
    const effect = stmt.Effect === "Allow" ? "Allow" : stmt.Effect === "Deny" ? "Deny" : "Unknown";
    const actions = [...toStringList(stmt.Action), ...toStringList(stmt.Action === undefined ? stmt.NotAction : undefined)].slice(0, MAX_IAM_ACTIONS);
    const resources = toStringList(stmt.Resource).slice(0, MAX_IAM_ACTIONS);
    statements.push({ effect, actions, resources, hasCondition: stmt.Condition !== undefined });
    if (effect === "Allow") {
      const onAllResources = resources.length === 0 || resources.includes("*");
      for (const a of actions) {
        if (a === "*" || a.endsWith(":*")) {
          if (onAllResources) wildcardActions.add(a);
          if (a === "*") admin = true;
        }
      }
    }
    const principal = cloudRec(stmt.Principal);
    for (const key of ["AWS", "Service", "Federated", "CanonicalUser"]) {
      for (const p of toStringList(principal[key])) trustedPrincipals.add(p);
    }
  }
  return { statements, wildcardActions: [...wildcardActions], isAdministratorEquivalent: admin, trustedPrincipals: [...trustedPrincipals] };
}

/** Broad-trust verdict for a trust policy (§42): assumption granted to
 *  "*", an external account root without an external-ID condition, or
 *  an anonymous principal. Evidence only — no assumption is attempted. */
export function hasBroadTrust(policy: ParsedIamPolicy): boolean {
  return policy.trustedPrincipals.some((p) => p === "*" || p.includes(":root") || p.toLowerCase().includes("anonymous"));
}

/** A secret-reference NAME (§6): an opaque identifier into the secret
 *  manager. Anything that looks like key material (long base64/hex
 *  blobs, AWS key prefixes, PEM headers, Azure/GCP secret shapes) is
 *  NOT a reference and is rejected wherever a reference is expected —
 *  this is the mechanical half of the credential-leak test (§100). */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/, // AWS access key id
  /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /AIza[0-9A-Za-z\-_]{35}/, // Google API key shape
  /(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40,}(?![A-Za-z0-9/+=])/, // long base64-ish blob
  /eyJ[A-Za-z0-9_-]{10,}\./, // JWT
];

export function looksLikeSecretValue(value: string): boolean {
  return SECRET_VALUE_PATTERNS.some((re) => re.test(value));
}

/** Redact secret-SHAPED substrings (defense in depth on top of the
 *  Prompt 12/13 text redactors, which key some patterns to assignment
 *  context): a bare key-shaped value in provider metadata is replaced
 *  wholesale — §100's leak test requires the VALUE to be absent, not
 *  merely unlabeled. */
export function redactSecretShapes(text: string): string {
  let out = text;
  for (const re of SECRET_VALUE_PATTERNS) out = out.replace(new RegExp(re.source, "g"), "[REDACTED]");
  return out;
}

export function isValidCredentialReference(value: string): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length > 300) return false;
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:/@-]*$/.test(value)) return false;
  return !looksLikeSecretValue(value);
}
