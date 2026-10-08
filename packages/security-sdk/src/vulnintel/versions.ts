import type { AffectedRangeData } from "./types";

/**
 * VersionComparisonService (Prompt 30 §34–§39).
 *
 * Naive string comparison is forbidden: "1.10.0" > "1.9.0" numerically,
 * and ecosystems disagree about qualifiers (Maven `1.0-rc1` < `1.0`,
 * PEP 440 `1.0rc1` < `1.0`, Go pseudo-versions, NuGet 4-part versions).
 * This module implements documented per-ecosystem semantics:
 *  - semver family (npm, cargo, golang, nuget, composer, generic):
 *    dotted numeric core + prerelease ordering.
 *  - pypi: PEP 440-lite (epoch, release tuple, a/b/c/rc pre, .post, .dev).
 *  - maven: Maven ComparableVersion token rules (qualifier ladder
 *    alpha < beta < milestone < rc < snapshot < release < sp).
 *  - deb/rpm/os: token comparison fallback (documented approximation).
 * Unparseable versions compare as UNKNOWN — callers must surface
 * UNCERTAIN rather than guess (§52).
 */

export type VersionCompareResult = -1 | 0 | 1 | null; // null = not comparable

interface SemverParts { core: number[]; pre: (string | number)[]; }

function parseSemver(raw: string): SemverParts | null {
  const v = raw.trim().replace(/^v(?=\d)/, "");
  const [mainPart, buildPart] = v.split("+", 2);
  void buildPart;
  const [coreStr, preStr] = (mainPart ?? "").split("-", 2);
  const coreSegs = (coreStr ?? "").split(".");
  if (coreSegs.some((s) => !/^\d+$/.test(s)) || coreSegs.length === 0) return null;
  const core = coreSegs.map(Number);
  const pre: (string | number)[] = [];
  if (preStr) {
    for (const seg of preStr.split(".")) {
      if (/^\d+$/.test(seg)) pre.push(Number(seg));
      else if (/^[0-9A-Za-z-]+$/.test(seg)) pre.push(seg.toLowerCase());
      else return null;
    }
  }
  return { core, pre };
}

function compareSemver(a: SemverParts, b: SemverParts): -1 | 0 | 1 {
  const len = Math.max(a.core.length, b.core.length);
  for (let i = 0; i < len; i++) {
    const d = (a.core[i] ?? 0) - (b.core[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1; // release > prerelease
  if (b.pre.length === 0) return -1;
  const plen = Math.max(a.pre.length, b.pre.length);
  for (let i = 0; i < plen; i++) {
    const x = a.pre[i]; const y = b.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (typeof x === "number" && typeof y === "number") { if (x !== y) return x < y ? -1 : 1; }
    else if (typeof x === "number") return -1; // numeric < alphanumeric
    else if (typeof y === "number") return 1;
    else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// ------------------------------ PEP 440-lite ------------------------------

interface Pep440 { epoch: number; release: number[]; pre: [string, number] | null; post: number | null; dev: number | null; }

function parsePep440(raw: string): Pep440 | null {
  let v = raw.trim().toLowerCase();
  if (!v) return null;
  let epoch = 0;
  const epochMatch = v.match(/^(\d+)!/);
  if (epochMatch) { epoch = Number(epochMatch[1]); v = v.slice(epochMatch[0].length); }
  const m = v.match(/^(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+))?(?:[-_.]?(post)[-_.]?(\d+))?(?:[-_.]?(dev)[-_.]?(\d+))?$/);
  if (!m) return null;
  const release = m[1]!.split(".").map(Number);
  const preNorm: Record<string, string> = { a: "a", alpha: "a", b: "b", beta: "b", c: "rc", rc: "rc", pre: "rc", preview: "rc" };
  const pre: [string, number] | null = m[2] ? [preNorm[m[2]]!, Number(m[3] ?? 0)] : null;
  const post = m[4] ? Number(m[5] ?? 0) : null;
  const dev = m[6] ? Number(m[7] ?? 0) : null;
  return { epoch, release, pre, post, dev };
}

function comparePep440(a: Pep440, b: Pep440): -1 | 0 | 1 {
  if (a.epoch !== b.epoch) return a.epoch < b.epoch ? -1 : 1;
  const len = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < len; i++) {
    const d = (a.release[i] ?? 0) - (b.release[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  const preRank = (p: [string, number] | null, dev: number | null): [number, string, number] => {
    if (p) return [1, p[0], p[1]];
    if (dev !== null) return [0, "", 0]; // dev-only sorts before pre-releases
    return [2, "", 0]; // plain release after pre-releases
  };
  const pa = preRank(a.pre, a.dev); const pb = preRank(b.pre, b.dev);
  if (pa[0] !== pb[0]) return pa[0] < pb[0] ? -1 : 1;
  if (pa[1] !== pb[1]) return pa[1] < pb[1] ? -1 : 1;
  if (pa[2] !== pb[2]) return pa[2] < pb[2] ? -1 : 1;
  // dev sorts before the same version without dev
  const da = a.dev ?? Number.POSITIVE_INFINITY; const db = b.dev ?? Number.POSITIVE_INFINITY;
  if (da !== db) return da < db ? -1 : 1;
  const poa = a.post ?? -1; const pob = b.post ?? -1;
  if (poa !== pob) return poa < pob ? -1 : 1;
  return 0;
}

// ------------------------------ Maven tokens ------------------------------

const MAVEN_QUALIFIER_RANK: Record<string, number> = {
  alpha: 0, a: 0, beta: 1, b: 1, milestone: 2, m: 2, rc: 3, cr: 3,
  snapshot: 4, "": 5, ga: 5, final: 5, release: 5, sp: 6,
};

function mavenTokens(raw: string): (number | string)[] {
  const tokens: (number | string)[] = [];
  for (const part of raw.trim().toLowerCase().split(/[.-]/)) {
    if (part === "") continue;
    // split digit/letter transitions: "rc1" -> ["rc", 1], "1a" -> [1, "a"]
    const pieces = part.match(/\d+|[a-z]+/g) ?? [part];
    for (const piece of pieces) tokens.push(/^\d+$/.test(piece) ? Number(piece) : piece);
  }
  return tokens;
}

function compareMaven(a: string, b: string): -1 | 0 | 1 | null {
  const ta = mavenTokens(a); const tb = mavenTokens(b);
  if (!ta.length || !tb.length) return null;
  const len = Math.max(ta.length, tb.length);
  for (let i = 0; i < len; i++) {
    const x = ta[i]; const y = tb[i];
    if (x === undefined && y === undefined) return 0;
    // Missing token: numeric context -> 0, qualifier context -> release rank
    const xVal: number | string = x === undefined ? (typeof y === "number" ? 0 : "") : x;
    const yVal: number | string = y === undefined ? (typeof x === "number" ? 0 : "") : y;
    if (typeof xVal === "number" && typeof yVal === "number") {
      if (xVal !== yVal) return xVal < yVal ? -1 : 1;
    } else if (typeof xVal === "string" && typeof yVal === "string") {
      const rx = MAVEN_QUALIFIER_RANK[xVal]; const ry = MAVEN_QUALIFIER_RANK[yVal];
      if (rx !== undefined && ry !== undefined) { if (rx !== ry) return rx < ry ? -1 : 1; }
      else if (xVal !== yVal) return xVal < yVal ? -1 : 1;
    } else {
      return typeof xVal === "number" ? 1 : -1; // qualifier < number segment boundary per Maven rules (approximation)
    }
  }
  return 0;
}

// ------------------------------ generic tokens ------------------------------

function compareTokenFallback(a: string, b: string): -1 | 0 | 1 | null {
  const ta = a.trim().split(/[.\-_+]/).filter(Boolean);
  const tb = b.trim().split(/[.\-_+]/).filter(Boolean);
  if (!ta.length || !tb.length) return null;
  const len = Math.max(ta.length, tb.length);
  for (let i = 0; i < len; i++) {
    const x = ta[i]; const y = tb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (/^\d+$/.test(x) && /^\d+$/.test(y)) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Compare two versions with ecosystem semantics (§34).
 * Returns -1 | 0 | 1, or null when either version is not parseable in
 * that ecosystem — callers must treat null as UNCERTAIN (§52).
 */
export function compareVersionsForEcosystem(a: string, b: string, ecosystem?: string): VersionCompareResult {
  if (!a || !b) return null;
  const eco = (ecosystem ?? "generic").toLowerCase();
  if (eco === "pypi") {
    const pa = parsePep440(a); const pb = parsePep440(b);
    return pa && pb ? comparePep440(pa, pb) : null;
  }
  if (eco === "maven") return compareMaven(a, b);
  if (["npm", "cargo", "golang", "go", "nuget", "composer", "rubygems", "gem", "generic"].includes(eco)) {
    const pa = parseSemver(a); const pb = parseSemver(b);
    if (pa && pb) return compareSemver(pa, pb);
    return compareTokenFallback(a, b);
  }
  // deb / rpm / os / container packages: token fallback (documented approximation)
  const pa = parseSemver(a); const pb = parseSemver(b);
  if (pa && pb) return compareSemver(pa, pb);
  return compareTokenFallback(a, b);
}

export function versionEquals(a: string, b: string, ecosystem?: string): boolean | null {
  const c = compareVersionsForEcosystem(a, b, ecosystem);
  return c === null ? null : c === 0;
}

// ------------------------------ Range evaluation ------------------------------

export type RangeVerdict = "AFFECTED" | "NOT_AFFECTED" | "UNCERTAIN";

export interface RangeEvaluation {
  verdict: RangeVerdict;
  /** Which range decided it (index into the evaluated set), when one did. */
  decidedBy?: number;
  reasons: string[];
}

/**
 * Evaluate ONE version against ONE affected range (§35).
 * Semantics: [introducedVersion, fixedVersion) ∪ (…, lastAffectedVersion].
 * introducedVersion absent ⇒ affected from the beginning of the branch.
 * A range with no machine-checkable bounds is UNCERTAIN — its expression
 * is preserved for a human, never guessed (§52).
 */
export function evaluateRange(version: string, range: AffectedRangeData): RangeEvaluation {
  const eco = range.ecosystem;
  const reasons: string[] = [];
  const hasBounds = !!(range.introducedVersion || range.fixedVersion || range.lastAffectedVersion);
  if (!hasBounds) {
    return { verdict: "UNCERTAIN", reasons: [`range from ${range.source} carries no machine-checkable bounds (expression: ${range.rangeExpression ?? "none"})`] };
  }
  if (range.introducedVersion) {
    const c = compareVersionsForEcosystem(version, range.introducedVersion, eco);
    if (c === null) return { verdict: "UNCERTAIN", reasons: [`version ${version} is not comparable with introduced ${range.introducedVersion} (${eco ?? "generic"} semantics)`] };
    if (c < 0) { reasons.push(`${version} < introduced ${range.introducedVersion}`); return { verdict: "NOT_AFFECTED", reasons }; }
    reasons.push(`${version} >= introduced ${range.introducedVersion}`);
  }
  if (range.fixedVersion) {
    const c = compareVersionsForEcosystem(version, range.fixedVersion, eco);
    if (c === null) return { verdict: "UNCERTAIN", reasons: [`version ${version} is not comparable with fixed ${range.fixedVersion}`] };
    if (c >= 0) { reasons.push(`${version} >= fixed ${range.fixedVersion} — fix applied`); return { verdict: "NOT_AFFECTED", reasons }; }
    reasons.push(`${version} < fixed ${range.fixedVersion}`);
  }
  if (range.lastAffectedVersion) {
    const c = compareVersionsForEcosystem(version, range.lastAffectedVersion, eco);
    if (c === null) return { verdict: "UNCERTAIN", reasons: [`version ${version} is not comparable with lastAffected ${range.lastAffectedVersion}`] };
    if (c > 0) { reasons.push(`${version} > lastAffected ${range.lastAffectedVersion}`); return { verdict: "NOT_AFFECTED", reasons }; }
    reasons.push(`${version} <= lastAffected ${range.lastAffectedVersion}`);
  }
  return { verdict: "AFFECTED", reasons };
}

/**
 * Evaluate a version against ALL ranges of one product (§39): branches
 * are independent. AFFECTED wins; else NOT_AFFECTED only when at least
 * one range evaluated decisively and none was uncertain-only; else
 * UNCERTAIN.
 */
export function evaluateRanges(version: string, ranges: AffectedRangeData[]): RangeEvaluation {
  const reasons: string[] = [];
  let sawNotAffected = false;
  let sawUncertain = false;
  for (let i = 0; i < ranges.length; i++) {
    const ev = evaluateRange(version, ranges[i]!);
    reasons.push(`range[${i}] (${ranges[i]!.source}): ${ev.verdict} — ${ev.reasons.join("; ")}`);
    if (ev.verdict === "AFFECTED") return { verdict: "AFFECTED", decidedBy: i, reasons };
    if (ev.verdict === "NOT_AFFECTED") sawNotAffected = true;
    else sawUncertain = true;
  }
  if (sawNotAffected && !sawUncertain) return { verdict: "NOT_AFFECTED", reasons };
  if (sawNotAffected && sawUncertain) return { verdict: "UNCERTAIN", reasons: [...reasons, "some branches evaluated NOT_AFFECTED but others were not machine-checkable — not claimed unaffected (§52)"] };
  return { verdict: "UNCERTAIN", reasons };
}
