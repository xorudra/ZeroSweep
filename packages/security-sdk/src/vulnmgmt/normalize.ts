/**
 * Identifier normalization (Prompt 11 §23–§27, §35). CVE / CWE / CPE /
 * CVSS identifiers arrive from scanners in inconsistent shapes; the
 * intelligence layer keys on ONE canonical form per identifier. Anything
 * that does not parse stays undefined — identifiers are never "repaired"
 * into plausible-looking values.
 */

const CVE_RE = /^CVE-(\d{4})-(\d{4,})$/i;

/** Canonical CVE id: `CVE-YYYY-NNNN+` upper-cased. Accepts bare years /
 *  numbers from scanner fields; rejects anything else. */
export function normalizeCveId(raw: string | undefined | null): string | undefined {
  if (!raw) return undefined;
  const m = CVE_RE.exec(raw.trim());
  if (!m) return undefined;
  const year = Number(m[1]);
  if (year < 1999 || year > 2100) return undefined;
  return `CVE-${m[1]}-${m[2]}`;
}

/** Extract every distinct canonical CVE id mentioned in free text
 *  (scanner descriptions frequently embed several). */
export function extractCveIds(text: string | undefined | null): string[] {
  if (!text) return [];
  const out = new Set<string>();
  for (const m of text.matchAll(/CVE-\d{4}-\d{4,}/gi)) {
    const id = normalizeCveId(m[0]);
    if (id) out.add(id);
  }
  return [...out];
}

const CWE_RE = /^(?:CWE-)?(\d{1,6})$/i;

/** Canonical CWE id: `CWE-79`. Accepts `79`, `CWE-79`, `cwe-79`. */
export function normalizeCweId(raw: string | number | undefined | null): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  const m = CWE_RE.exec(String(raw).trim());
  if (!m) return undefined;
  const n = Number(m[1]);
  if (!Number.isInteger(n) || n <= 0) return undefined;
  return `CWE-${n}`;
}

export interface CpeParts {
  part: "a" | "h" | "o";
  vendor: string;
  product: string;
  version?: string;
  update?: string;
  edition?: string;
  language?: string;
  swEdition?: string;
  targetSw?: string;
  targetHw?: string;
  other?: string;
}

/** Parse a CPE 2.3 formatted string OR a legacy CPE 2.2 URI binding
 *  (`cpe:/a:vendor:product:version`) into parts. Returns undefined for
 *  anything malformed — CPE correlation (§33) must never guess. */
export function parseCpe(raw: string | undefined | null): CpeParts | undefined {
  if (!raw) return undefined;
  const value = raw.trim();
  if (value.toLowerCase().startsWith("cpe:2.3:")) {
    const fields = splitCpe23(value.slice("cpe:2.3:".length));
    if (!fields || fields.length !== 11) return undefined;
    const [part, vendor, product, version, update, edition, language, swEdition, targetSw, targetHw, other] = fields;
    if (!part || !/^[aho]$/i.test(part) || !vendor || !product) return undefined;
    const star = (v?: string) => (v === undefined || v === "*" || v === "" ? undefined : v);
    return {
      part: part.toLowerCase() as CpeParts["part"],
      vendor: unquote(vendor), product: unquote(product),
      version: star(version), update: star(update), edition: star(edition),
      language: star(language), swEdition: star(swEdition), targetSw: star(targetSw),
      targetHw: star(targetHw), other: star(other),
    };
  }
  if (value.toLowerCase().startsWith("cpe:/")) {
    const fields = value.slice("cpe:/".length).split(":");
    const [part, vendor, product, version] = fields;
    if (!part || !/^[aho]$/i.test(part) || !vendor || !product) return undefined;
    return {
      part: part.toLowerCase() as CpeParts["part"],
      vendor: decodeURIComponent(vendor), product: decodeURIComponent(product),
      ...(version ? { version: decodeURIComponent(version) } : {}),
    };
  }
  return undefined;
}

function splitCpe23(rest: string): string[] | undefined {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (ch === "\\" && i + 1 < rest.length) { cur += rest[++i]; continue; }
    if (ch === ":") { out.push(cur); cur = ""; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

function unquote(v: string): string {
  return v.replace(/\\(.)/g, "$1");
}

/** Canonical CPE 2.3 string from parts (absent fields become `*`). */
export function formatCpe(parts: CpeParts): string {
  const q = (v: string) => v.replace(/\\/g, "\\\\").replace(/:/g, "\\:");
  const f = (v?: string) => (v === undefined || v === "" ? "*" : q(v));
  return [
    "cpe:2.3", parts.part, q(parts.vendor), q(parts.product),
    f(parts.version), f(parts.update), f(parts.edition), f(parts.language),
    f(parts.swEdition), f(parts.targetSw), f(parts.targetHw), f(parts.other),
  ].join(":");
}

export interface CvssRecord {
  version: string; // "2.0" | "3.0" | "3.1" | "4.0" — preserved, never converted (§26)
  baseScore: number;
  vector: string;
  source: string; // SCANNER | NVD | ...
}

/** Validate + normalize a CVSS score/vector pair from a source. The
 *  version is derived from the vector prefix when present; a score
 *  without any vector is kept but versioned "unknown". Scores outside
 *  0..10 are rejected, never clamped into plausibility. */
export function normalizeCvss(input: { score?: number | string; vector?: string; version?: string; source: string }): CvssRecord | undefined {
  const score = typeof input.score === "string" ? Number(input.score) : input.score;
  if (score === undefined || !Number.isFinite(score) || score < 0 || score > 10) return undefined;
  const vector = (input.vector ?? "").trim();
  let version = input.version?.trim() || "";
  if (!version && vector) {
    const m = /^CVSS:(\d\.\d)\//.exec(vector);
    if (m) version = m[1];
    else if (/^AV:/.test(vector)) version = "2.0"; // CVSS v2 vectors carry no prefix
  }
  return { version: version || "unknown", baseScore: Math.round(score * 10) / 10, vector, source: input.source };
}
