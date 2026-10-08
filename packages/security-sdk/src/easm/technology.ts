import type { EasmTechnologyConfidence } from "./types";
import { normalizeTechnologyName } from "./normalize";

/**
 * Technology intelligence (Prompt 29 §53–§58). Confidence rises only
 * through INDEPENDENT sources (§56/§145) — the same source repeating
 * itself changes nothing. Version discipline (§57/§146): a version
 * is claimed only when evidence explicitly carries one (e.g. a
 * versioned banner/header); a product-family fingerprint leaves the
 * version unknown.
 */

export interface TechnologyEvidenceInput {
  /** Normalized technology name as detected. */
  technology: string;
  /** Independent evidence source (adapter slug / evidence class). */
  source: string;
  /** Version exactly as evidenced, when the evidence states one. */
  version?: string | null;
  /** True when the evidence is a family-only fingerprint (no version claim possible). */
  familyOnly?: boolean;
}

export interface TechnologyResolution {
  technology: string;
  normalizedName: string;
  version: string | null;
  confidence: EasmTechnologyConfidence;
  sources: string[];
}

const LADDER: EasmTechnologyConfidence[] = ["LOW", "MEDIUM", "HIGH"];

export function resolveTechnology(observations: TechnologyEvidenceInput[]): TechnologyResolution | null {
  if (observations.length === 0) return null;
  const normalizedName = normalizeTechnologyName(observations[0]!.technology);
  const same = observations.filter((o) => normalizeTechnologyName(o.technology) === normalizedName);
  const sources = [...new Set(same.map((o) => o.source))].sort();
  // §56: 1 source = LOW, 2 independent = MEDIUM, 3+ = HIGH.
  const confidence = LADDER[Math.min(sources.length - 1, 2)]!;
  // §57: version only from non-family-only evidence that states one;
  // conflicting versioned claims resolve to null (disagreement = unknown).
  const versioned = same.filter((o) => !o.familyOnly && o.version != null && o.version !== "");
  const versions = [...new Set(versioned.map((o) => o.version!.trim()))];
  const version = versions.length === 1 ? versions[0]! : null;
  return { technology: observations[0]!.technology, normalizedName, version, confidence, sources };
}

/** Group raw observations per technology and resolve each (§54). */
export function resolveTechnologies(observations: TechnologyEvidenceInput[]): TechnologyResolution[] {
  const groups = new Map<string, TechnologyEvidenceInput[]>();
  for (const o of observations) {
    const key = normalizeTechnologyName(o.technology);
    const list = groups.get(key) ?? [];
    list.push(o);
    groups.set(key, list);
  }
  return [...groups.values()]
    .map((g) => resolveTechnology(g))
    .filter((r): r is TechnologyResolution => r !== null)
    .sort((a, b) => a.normalizedName.localeCompare(b.normalizedName));
}
