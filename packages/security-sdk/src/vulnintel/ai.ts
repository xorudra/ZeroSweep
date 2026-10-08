/**
 * AI vulnerability copilot support (Prompt 30 §107–§111).
 *
 * The copilot is GROUNDED in stored deterministic values: numbers come
 * from records, never from a model (§151). It must not invent a patch,
 * fixed version, or mitigation (§109): with no verified fix recorded the
 * answer is the verbatim sentence below. It explains exploitation RISK
 * but never produces operational exploit instructions (§110).
 *
 * Natural-language questions translate into a DETERMINISTIC query plan
 * (§111) — the same filters the search API applies (§102). Unknown
 * phrasings yield no plan (the caller asks a clarifying question)
 * instead of a guessed query.
 */

export const NO_VERIFIED_FIX_SENTENCE = "No verified fix is currently recorded.";

export interface VulnQueryPlan {
  kev?: boolean;
  minEpss?: number;
  patchStatus?: string;
  internetExposed?: boolean;
  component?: string;
  cveId?: string;
  reachability?: string;
  minAffectedAssets?: number;
  productionOnly?: boolean;
}

/** §111: deterministic NL → query plan translation. */
export function translateVulnQuestion(question: string): VulnQueryPlan | null {
  const q = question.toLowerCase();
  const plan: VulnQueryPlan = {};
  let matched = false;
  const cveMatch = q.match(/cve-\d{4}-\d{4,}/);
  if (cveMatch) { plan.cveId = cveMatch[0].toUpperCase(); matched = true; }
  if (/\bkev\b|known exploited/.test(q)) { plan.kev = true; matched = true; }
  if (/internet[- ]facing|internet exposed|externally exposed/.test(q)) { plan.internetExposed = true; matched = true; }
  if (/with patch|patch available|has a patch|fixed version available/.test(q)) { plan.patchStatus = "FIXED_VERSION_AVAILABLE"; matched = true; }
  if (/no known fix|no fix|unpatched|without a patch/.test(q)) { plan.patchStatus = "NO_KNOWN_FIX"; matched = true; }
  const epssMatch = q.match(/epss[^0-9]*?(?:>|above|over|greater than)?\s*(0?\.\d+|\d{1,3}\s*%)/);
  if (/epss/.test(q)) {
    matched = true;
    if (epssMatch) {
      const raw = epssMatch[1]!;
      plan.minEpss = raw.includes("%") ? Number(raw.replace("%", "").trim()) / 100 : Number(raw);
    } else if (/high epss/.test(q)) plan.minEpss = 0.5;
  }
  const compMatch = q.match(/component[:\s]+([a-z0-9._/-]+)/);
  if (compMatch) { plan.component = compMatch[1]; matched = true; }
  if (/reachable/.test(q)) { plan.reachability = "REACHABLE"; matched = true; }
  const assetMatch = q.match(/more than (\d+) assets|affect(?:s|ing)? (\d+)\+? assets/);
  if (assetMatch) { plan.minAffectedAssets = Number(assetMatch[1] ?? assetMatch[2]); matched = true; }
  if (/production/.test(q)) { plan.productionOnly = true; matched = true; }
  return matched ? plan : null;
}

export interface GroundedCveContext {
  cveId: string;
  hasRecord: boolean;
  description?: string;
  cvss?: { score: number; version: string; source: string };
  epss?: { score: number; percentile: number; date: string; freshness: string };
  kevListed: boolean;
  patchStatus: string;
  fixedVersion?: string;
  conflictingFixedVersions?: Record<string, { source: string; fixedVersion: string }[]>;
  mitigation?: string;
  affectedAssetsConfirmed: number;
  affectedAssetsPotential: number;
  exploitMaturity?: string;
}

export interface GroundedAnswer {
  answer: string;
  citations: string[];
  /** Always false: the copilot recommends/explains, never executes (§110 companion rule). */
  executed: false;
}

/** §107: "Why is this CVE important?" — composed strictly from context. */
export function answerWhyImportant(ctx: GroundedCveContext): GroundedAnswer {
  if (!ctx.hasRecord) {
    return { answer: `No intelligence record for ${ctx.cveId} exists in the local dataset — importance cannot be assessed from stored data.`, citations: [], executed: false };
  }
  const parts: string[] = [];
  const citations: string[] = ["cve-intelligence"];
  if (ctx.cvss) { parts.push(`CVSS ${ctx.cvss.score} (v${ctx.cvss.version}, source ${ctx.cvss.source})`); citations.push("cvss"); }
  if (ctx.kevListed) { parts.push("CISA KEV-listed (known exploited)"); citations.push("kev"); }
  if (ctx.epss) { parts.push(`EPSS ${ctx.epss.score} (percentile ${ctx.epss.percentile}, ${ctx.epss.date}${ctx.epss.freshness === "STALE" ? ", STALE" : ""})`); citations.push("epss"); }
  if (ctx.exploitMaturity && ctx.exploitMaturity !== "UNKNOWN") { parts.push(`exploit maturity ${ctx.exploitMaturity} per trusted intelligence`); citations.push("exploit-context"); }
  parts.push(`${ctx.affectedAssetsConfirmed} confirmed affected assets, ${ctx.affectedAssetsPotential} potential`);
  citations.push("sbom-correlation");
  return { answer: `${ctx.cveId} matters because: ${parts.join("; ")}.`, citations, executed: false };
}

/** §109/§143/§150: the fix question. Without a verified fix the answer
 *  is the exact governed sentence — never an invented version. */
export function answerFixQuestion(ctx: GroundedCveContext): GroundedAnswer {
  if (ctx.conflictingFixedVersions && Object.keys(ctx.conflictingFixedVersions).length > 0) {
    const detail = Object.entries(ctx.conflictingFixedVersions)
      .map(([k, entries]) => `${k}: ${entries.map((e) => `${e.fixedVersion} (${e.source})`).join(" vs ")}`)
      .join("; ");
    return {
      answer: `Sources disagree on the fixed version for ${ctx.cveId} (${detail}). No single version is presented as definitive until the conflict is reviewed (§86).`,
      citations: ["patch-intelligence", "intelligence-conflict"],
      executed: false,
    };
  }
  if (ctx.fixedVersion) {
    return { answer: `The recorded fixed version for ${ctx.cveId} is ${ctx.fixedVersion} (from a reliable advisory source).`, citations: ["patch-intelligence"], executed: false };
  }
  if (ctx.mitigation) {
    return { answer: `${NO_VERIFIED_FIX_SENTENCE} A vendor/authoritative mitigation is recorded: ${ctx.mitigation}`, citations: ["patch-intelligence"], executed: false };
  }
  return { answer: NO_VERIFIED_FIX_SENTENCE, citations: ["patch-intelligence"], executed: false };
}

/** §151: numeric questions are answered from stored values verbatim. */
export function answerNumericQuestion(ctx: GroundedCveContext, metric: "epss" | "cvss"): GroundedAnswer {
  if (metric === "epss") {
    if (!ctx.epss) return { answer: `No EPSS assessment is stored for ${ctx.cveId}; no value can be reported (absence is never rendered as 0).`, citations: [], executed: false };
    return { answer: `The stored EPSS for ${ctx.cveId} is ${ctx.epss.score} (percentile ${ctx.epss.percentile}) as of ${ctx.epss.date}${ctx.epss.freshness === "STALE" ? " — this value is STALE" : ""}.`, citations: ["epss"], executed: false };
  }
  if (!ctx.cvss) return { answer: `No CVSS assessment is stored for ${ctx.cveId}.`, citations: [], executed: false };
  return { answer: `The stored preferred CVSS for ${ctx.cveId} is ${ctx.cvss.score} (v${ctx.cvss.version}, source ${ctx.cvss.source}).`, citations: ["cvss"], executed: false };
}
