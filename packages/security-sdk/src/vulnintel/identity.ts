import { parseCpe, formatCpe } from "../vulnmgmt/normalize";
import type { MatchConfidence } from "./types";

/**
 * Software component identity (Prompt 30 §28–§33, §49–§50).
 *
 * A component is identified across name / PURL / CPE / ecosystem /
 * vendor+product. PURL is the normalized package identity (§30); CPE is
 * the vulnerability-matching identity where provider data uses it (§31).
 * Identity resolution reports a CONFIDENCE — equivalent identifiers are
 * the same component; similar names are merely similar (§52).
 */

export interface PurlParts {
  type: string; // npm | pypi | maven | nuget | gem | golang | cargo | composer | deb | rpm | generic …
  namespace?: string;
  name: string;
  version?: string;
  qualifiers: Record<string, string>;
  subpath?: string;
}

/** PURL types whose names are case-insensitive per the PURL spec. */
const PURL_LOWERCASE_NAME_TYPES = new Set(["npm", "pypi", "gem", "nuget", "cargo", "composer", "golang", "maven", "deb", "rpm", "generic"]);

/**
 * Parse + normalize a Package URL (§30). Returns undefined for malformed
 * input — identity is never guessed. Normalization: scheme/type/name
 * casing per spec, PyPI name separator folding (`-`/`_`/`.` → `-`),
 * percent-decoding of name/namespace, qualifier sorting.
 */
export function parsePurl(raw: string | undefined | null): PurlParts | undefined {
  if (!raw) return undefined;
  const value = raw.trim();
  if (!value.toLowerCase().startsWith("pkg:")) return undefined;
  let rest = value.slice(4);
  // Strip fragment (subpath) first, then query (qualifiers).
  let subpath: string | undefined;
  const hashIdx = rest.indexOf("#");
  if (hashIdx >= 0) { subpath = rest.slice(hashIdx + 1) || undefined; rest = rest.slice(0, hashIdx); }
  const qualifiers: Record<string, string> = {};
  const qIdx = rest.indexOf("?");
  if (qIdx >= 0) {
    const qs = rest.slice(qIdx + 1); rest = rest.slice(0, qIdx);
    for (const pair of qs.split("&")) {
      if (!pair) continue;
      const eq = pair.indexOf("=");
      if (eq <= 0) return undefined;
      qualifiers[safeDecode(pair.slice(0, eq)).toLowerCase()] = safeDecode(pair.slice(eq + 1));
    }
  }
  const segments = rest.split("/").filter((s) => s.length > 0);
  if (segments.length < 2) return undefined;
  const type = segments[0]!.toLowerCase();
  if (!/^[a-z][a-z0-9.+-]*$/.test(type)) return undefined;
  let nameVersion = segments[segments.length - 1]!;
  const namespaceSegments = segments.slice(1, -1);
  let version: string | undefined;
  const atIdx = nameVersion.lastIndexOf("@");
  if (atIdx > 0) { version = safeDecode(nameVersion.slice(atIdx + 1)) || undefined; nameVersion = nameVersion.slice(0, atIdx); }
  let name = safeDecode(nameVersion);
  let namespace = namespaceSegments.map(safeDecode).join("/") || undefined;
  if (PURL_LOWERCASE_NAME_TYPES.has(type)) {
    name = name.toLowerCase();
    if (namespace) namespace = namespace.toLowerCase();
  }
  if (type === "pypi") name = name.toLowerCase().replace(/[-_.]+/g, "-");
  if (type === "maven" && namespace) { /* groupId kept verbatim (case-sensitive-ish in practice) */ }
  if (!name) return undefined;
  return { type, ...(namespace ? { namespace } : {}), name, ...(version ? { version } : {}), qualifiers, ...(subpath ? { subpath } : {}) };
}

function safeDecode(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** Canonical PURL string (§137: semantically equivalent PURLs normalize
 *  to the same string, hence the same component identity). */
export function formatPurl(parts: PurlParts): string {
  const ns = parts.namespace ? `${parts.namespace.split("/").map(encodeURIComponent).join("/")}/` : "";
  const ver = parts.version ? `@${encodeURIComponent(parts.version)}` : "";
  const qs = Object.keys(parts.qualifiers).sort().map((k) => `${k}=${encodeURIComponent(parts.qualifiers[k]!)}`).join("&");
  return `pkg:${parts.type}/${ns}${encodeURIComponent(parts.name)}${ver}${qs ? `?${qs}` : ""}${parts.subpath ? `#${parts.subpath}` : ""}`;
}

export function normalizePurl(raw: string | undefined | null): string | undefined {
  const parts = parsePurl(raw);
  return parts ? formatPurl(parts) : undefined;
}

/** Product key used across patch/advisory joins: `vendor:product`, lower. */
export function productKey(vendor: string, product: string): string {
  return `${vendor.trim().toLowerCase()}:${product.trim().toLowerCase()}`;
}

/** Normalized name for SoftwareProduct.normalizedName (§28). */
export function normalizedProductName(vendor: string, product: string): string {
  return productKey(vendor, product);
}

export interface ComponentIdentityInput {
  name: string;
  version?: string;
  ecosystem?: string;
  purl?: string;
  cpe?: string;
  vendor?: string;
  supplier?: string;
}

export interface ResolvedComponentIdentity {
  /** Stable identity key: canonical PURL when known, else CPE, else ecosystem:name@version. */
  identityKey: string;
  purl?: string;
  cpe?: string;
  productKey?: string;
  confidence: MatchConfidence;
  evidence: string[];
}

/**
 * SoftwareComponentIdentityService (§49): resolve a component's identity
 * from whatever identifiers are present. A canonical PURL is an EXACT
 * identity; a CPE is HIGH; ecosystem+name+version is MEDIUM (name
 * spellings vary); name alone is LOW.
 */
export function resolveComponentIdentity(input: ComponentIdentityInput): ResolvedComponentIdentity {
  const evidence: string[] = [];
  const purlParts = parsePurl(input.purl);
  const purl = purlParts ? formatPurl(purlParts) : undefined;
  if (input.purl && !purl) evidence.push(`PURL ${JSON.stringify(input.purl)} did not parse — ignored for identity`);
  const cpeParts = parseCpe(input.cpe);
  const cpe = cpeParts ? formatCpe(cpeParts) : undefined;
  if (input.cpe && !cpe) evidence.push(`CPE ${JSON.stringify(input.cpe)} did not parse — ignored for identity`);

  const vendor = input.vendor ?? cpeParts?.vendor ?? purlParts?.namespace;
  const prodKey = vendor ? productKey(vendor, input.name) : (cpeParts ? productKey(cpeParts.vendor, cpeParts.product) : undefined);

  if (purl) {
    evidence.push("identity anchored on canonical PURL (§30)");
    return { identityKey: purl, purl, ...(cpe ? { cpe } : {}), ...(prodKey ? { productKey: prodKey } : {}), confidence: "EXACT", evidence };
  }
  if (cpe) {
    evidence.push("identity anchored on canonical CPE (§31)");
    return { identityKey: cpe, cpe, ...(prodKey ? { productKey: prodKey } : {}), confidence: "HIGH", evidence };
  }
  const eco = (input.ecosystem ?? "generic").toLowerCase();
  if (input.version) {
    evidence.push("identity from ecosystem + name + version (no PURL/CPE supplied)");
    return { identityKey: `${eco}:${input.name.toLowerCase()}@${input.version}`, ...(prodKey ? { productKey: prodKey } : {}), confidence: "MEDIUM", evidence };
  }
  evidence.push("identity from name only — matches against this component must stay low-confidence (§52)");
  return { identityKey: `${eco}:${input.name.toLowerCase()}`, ...(prodKey ? { productKey: prodKey } : {}), confidence: "LOW", evidence };
}

/** §138: validate a CPE string for use in matching. Uses the governed
 *  parser — malformed or unsafe input (control chars, wildcards in
 *  vendor/product position) is rejected, never sanitized into a guess. */
export function validateCpe(raw: string | undefined | null): { ok: boolean; canonical?: string; reason?: string } {
  if (!raw) return { ok: false, reason: "empty CPE" };
  // eslint-disable-next-line no-control-regex -- detecting control chars IS the validation (§138)
  if (/[\u0000-\u001f\u007f]/.test(raw)) return { ok: false, reason: "control characters are not permitted in a CPE" };
  if (raw.length > 512) return { ok: false, reason: "CPE exceeds 512 characters" };
  const parts = parseCpe(raw);
  if (!parts) return { ok: false, reason: "not a parseable CPE 2.3 formatted string or 2.2 URI binding" };
  if (parts.vendor === "*" || parts.product === "*") return { ok: false, reason: "wildcard vendor/product cannot anchor a match" };
  return { ok: true, canonical: formatCpe(parts) };
}

/** §32: derive a PURL↔CPE identifier mapping with stated confidence. */
export function deriveIdentifierMapping(input: { purl?: string; cpe?: string }): {
  purl?: string; cpe?: string; vendor: string; product: string; ecosystem?: string; confidence: MatchConfidence;
} | undefined {
  const purlParts = parsePurl(input.purl);
  const cpeParts = parseCpe(input.cpe);
  if (!purlParts && !cpeParts) return undefined;
  const vendor = cpeParts?.vendor ?? purlParts?.namespace ?? "";
  const product = cpeParts?.product ?? purlParts?.name ?? "";
  if (!product) return undefined;
  const confidence: MatchConfidence = purlParts && cpeParts ? "HIGH" : purlParts ? "MEDIUM" : "MEDIUM";
  return {
    ...(purlParts ? { purl: formatPurl(purlParts) } : {}),
    ...(cpeParts ? { cpe: formatCpe(cpeParts) } : {}),
    vendor, product,
    ...(purlParts ? { ecosystem: purlParts.type } : {}),
    confidence,
  };
}
