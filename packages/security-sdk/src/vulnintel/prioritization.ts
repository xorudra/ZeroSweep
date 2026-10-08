import type { AdvisoryData, PatchRecordData, PatchStatus, ExploitMaturity } from "./types";

/**
 * Patch intelligence, prioritization and remediation recommendation
 * (Prompt 30 §40–§43, §79–§86, §91–§93).
 *
 * §85 is absolute: an exact fixed version is recommended ONLY when a
 * reliable source states it. §86: when sources disagree on the fix, the
 * conflict is shown — an uncertain fix is never presented as definitive.
 * §92: remediation order is NEVER CVSS alone.
 */

// ------------------------------ patch intelligence (§40–§43) ------------------------------

export function derivePatchRecords(advisories: AdvisoryData[]): PatchRecordData[] {
  const out: PatchRecordData[] = [];
  for (const adv of advisories) {
    for (const cveId of adv.cveIds) {
      for (const [pKey, fixed] of Object.entries(adv.fixedVersions)) {
        for (const fixedVersion of fixed) {
          out.push({
            cveId, productKey: pKey, fixedVersion, advisoryId: adv.advisoryId,
            status: "FIXED_VERSION_AVAILABLE", confidence: "HIGH", source: adv.source,
            ...(adv.publishedAt ? { releaseDate: adv.publishedAt } : {}),
          });
        }
      }
      for (const m of adv.mitigations) {
        out.push({
          cveId, productKey: m.productKey, mitigation: m.text, advisoryId: adv.advisoryId,
          status: "MITIGATION_ONLY", confidence: "MEDIUM", source: adv.source,
        });
      }
    }
  }
  return out;
}

export interface PatchAssessment {
  status: PatchStatus;
  /** The fixed version to cite — present ONLY when one reliable source states it and no trusted source disagrees (§85/§86). */
  fixedVersion?: string;
  fixedVersionsByProduct: Record<string, string[]>;
  conflictingFixedVersions?: Record<string, { source: string; fixedVersion: string }[]>;
  mitigation?: string;
  evidence: string[];
}

/** Combine patch records + advisory statements into one honest patch
 *  status for a CVE (§42). NO_KNOWN_FIX requires positive coverage: at
 *  least one advisory/intel record examined the CVE and offered no fix. */
export function assessPatchStatus(input: {
  patchRecords: PatchRecordData[];
  advisoriesExamined: number;
  intelRecordsExamined: number;
}): PatchAssessment {
  const evidence: string[] = [];
  const byProduct = new Map<string, { source: string; fixedVersion: string }[]>();
  let mitigation: string | undefined;
  for (const rec of input.patchRecords) {
    if (rec.fixedVersion) {
      (byProduct.get(rec.productKey) ?? byProduct.set(rec.productKey, []).get(rec.productKey)!).push({ source: rec.source, fixedVersion: rec.fixedVersion });
    }
    if (rec.mitigation && !mitigation) mitigation = rec.mitigation;
  }
  const fixedVersionsByProduct: Record<string, string[]> = {};
  const conflicts: Record<string, { source: string; fixedVersion: string }[]> = {};
  let agreedFixed: string | undefined;
  for (const [pKey, entries] of byProduct) {
    const distinct = [...new Set(entries.map((e) => e.fixedVersion))];
    fixedVersionsByProduct[pKey] = distinct;
    if (distinct.length > 1) conflicts[pKey] = entries;
    else if (distinct.length === 1 && !agreedFixed) agreedFixed = distinct[0];
  }
  const hasConflict = Object.keys(conflicts).length > 0;
  if (hasConflict) evidence.push("trusted sources disagree on the fixed version — conflict shown, no definitive fix presented (§86)");
  if (byProduct.size > 0 && !hasConflict) {
    evidence.push("fixed version stated by a reliable advisory source (§85)");
    return { status: "FIXED_VERSION_AVAILABLE", fixedVersion: agreedFixed, fixedVersionsByProduct, ...(mitigation ? { mitigation } : {}), evidence };
  }
  if (byProduct.size > 0 && hasConflict) {
    return { status: "UNKNOWN", fixedVersionsByProduct, conflictingFixedVersions: conflicts, ...(mitigation ? { mitigation } : {}), evidence };
  }
  if (mitigation) {
    evidence.push("a vendor/authoritative mitigation exists but no fixed version is recorded");
    return { status: "MITIGATION_ONLY", fixedVersionsByProduct, mitigation, evidence };
  }
  if (input.advisoriesExamined > 0 || input.intelRecordsExamined > 0) {
    evidence.push("advisories/intelligence examined and no fixed version or patch is recorded — NO_KNOWN_FIX (§42)");
    return { status: "NO_KNOWN_FIX", fixedVersionsByProduct, evidence };
  }
  evidence.push("no advisory or intelligence coverage for this CVE yet — patch status UNKNOWN, not NO_KNOWN_FIX");
  return { status: "UNKNOWN", fixedVersionsByProduct, evidence };
}

// ------------------------------ prioritization (§91–§93) ------------------------------

export interface PrioritizationSignals {
  cveId: string;
  cvssScore?: number;
  epssScore?: number; // absent stays absent — never defaulted to 0 in explanations
  kevListed: boolean;
  internetExposed: boolean;
  assetCriticality?: string; // CRITICAL | HIGH | MEDIUM | LOW | UNSPECIFIED
  verified: boolean;
  reachability?: string; // REACHABLE | POTENTIALLY_REACHABLE | NOT_REACHABLE | UNKNOWN
  exploitMaturity?: ExploitMaturity;
  patchStatus: PatchStatus;
  confirmedAffectedAssets: number;
  potentialAffectedAssets: number;
  ageDays?: number;
}

export interface VulnPrioritizationResult {
  cveId: string;
  /** Deterministic 0–100 contextual priority — NOT a CVSS restatement (§92). */
  priorityScore: number;
  priorityBand: "P0" | "P1" | "P2" | "P3" | "P4";
  /** §93: why, with the evidence behind each signal. */
  why: string[];
  riskSignals: string[];
  remediationAvailability: string;
}

/**
 * VulnerabilityPrioritizationService (§91). Deterministic weighted
 * signals: known exploitation and real exposure dominate; CVSS is one
 * input among many (§92/§148 — an internal low-criticality asset with
 * the same CVSS scores materially lower than an internet-facing
 * critical KEV asset).
 */
export function prioritizeVulnerability(s: PrioritizationSignals): VulnPrioritizationResult {
  const why: string[] = [];
  const riskSignals: string[] = [];
  let score = 0;

  if (s.cvssScore !== undefined) {
    const contribution = s.cvssScore * 2.5; // up to 25
    score += contribution;
    riskSignals.push(`CVSS ${s.cvssScore} contributes ${contribution.toFixed(1)}/25 — one signal among many (§92)`);
  } else {
    why.push("no CVSS assessment recorded — priority computed from remaining signals, CVSS absence is stated, not filled in");
  }
  if (s.kevListed) {
    score += 25;
    why.push("CISA KEV-listed: known exploited in the wild (+25)");
    riskSignals.push("KEV");
  }
  if (s.epssScore !== undefined) {
    const contribution = s.epssScore * 15;
    score += contribution;
    riskSignals.push(`EPSS ${(s.epssScore).toFixed(3)} contributes ${contribution.toFixed(1)}/15`);
    if (s.epssScore >= 0.5) why.push(`EPSS ${s.epssScore.toFixed(3)} — exploitation probability is high`);
  }
  if (s.internetExposed) { score += 12; why.push("affects at least one internet-facing asset (+12)"); riskSignals.push("INTERNET_EXPOSED"); }
  const critMap: Record<string, number> = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, UNSPECIFIED: 0 };
  const crit = critMap[s.assetCriticality ?? "UNSPECIFIED"] ?? 0;
  if (crit > 0) { score += crit; why.push(`highest affected-asset criticality ${s.assetCriticality} (+${crit})`); }
  if (s.verified) { score += 5; why.push("finding verified (+5)"); riskSignals.push("VERIFIED"); }
  if (s.reachability === "REACHABLE") { score += 5; why.push("vulnerable component assessed REACHABLE (+5)"); riskSignals.push("REACHABLE"); }
  else if (s.reachability === "POTENTIALLY_REACHABLE") { score += 2; why.push("component POTENTIALLY_REACHABLE (+2)"); }
  else if (s.reachability === "NOT_REACHABLE") { score -= 5; why.push("component assessed NOT_REACHABLE on positive evidence (−5)"); }
  if (s.exploitMaturity === "ACTIVE_EXPLOITATION_REPORTED") { score += 8; why.push("active exploitation reported by a trusted source (+8)"); riskSignals.push("ACTIVE_EXPLOITATION"); }
  else if (s.exploitMaturity === "FUNCTIONAL_REPORTED") { score += 5; why.push("functional exploit reported (+5)"); }
  else if (s.exploitMaturity === "PROOF_OF_CONCEPT_REPORTED") { score += 3; why.push("proof-of-concept exploit reported (+3)"); }
  const blast = Math.min(10, s.confirmedAffectedAssets * 2 + s.potentialAffectedAssets * 0.5);
  if (blast > 0) { score += blast; why.push(`blast radius: ${s.confirmedAffectedAssets} confirmed + ${s.potentialAffectedAssets} potential affected assets (+${blast.toFixed(1)})`); riskSignals.push("BLAST_RADIUS"); }
  if (s.ageDays !== undefined && s.ageDays > 90) { score += 3; why.push(`exposure age ${s.ageDays}d > 90d (+3)`); }

  score = Math.max(0, Math.min(100, Math.round(score * 10) / 10));
  const priorityBand = score >= 85 ? "P0" : score >= 65 ? "P1" : score >= 45 ? "P2" : score >= 25 ? "P3" : "P4";
  const remediationAvailability =
    s.patchStatus === "FIXED_VERSION_AVAILABLE" || s.patchStatus === "PATCH_AVAILABLE" ? "verified fix available"
    : s.patchStatus === "MITIGATION_ONLY" ? "mitigation only — no fixed version recorded"
    : s.patchStatus === "NO_KNOWN_FIX" ? "no known fix — isolate/monitor path (§84)"
    : "fix availability unknown";
  return { cveId: s.cveId, priorityScore: score, priorityBand, why, riskSignals, remediationAvailability };
}

// ------------------------------ remediation recommendation (§84–§86) ------------------------------

export interface RemediationRecommendation {
  action: "UPGRADE_TO_FIXED_VERSION" | "APPLY_VENDOR_PATCH" | "APPLY_VENDOR_MITIGATION" | "REMOVE_UNUSED_COMPONENT" | "ISOLATE_OR_RESTRICT_EXPOSURE" | "MONITOR_NO_FIX";
  /** Present ONLY when §85 is satisfied. */
  fixedVersion?: string;
  rationale: string;
}

export function recommendRemediation(input: {
  patch: PatchAssessment;
  reachability?: string;
  internetExposed: boolean;
  kevListed: boolean;
}): RemediationRecommendation {
  const { patch } = input;
  if (patch.status === "FIXED_VERSION_AVAILABLE" && patch.fixedVersion) {
    return { action: "UPGRADE_TO_FIXED_VERSION", fixedVersion: patch.fixedVersion, rationale: `upgrade to ${patch.fixedVersion} — the fixed version stated by a reliable advisory source (§85)` };
  }
  if (patch.status === "PATCH_AVAILABLE") {
    return { action: "APPLY_VENDOR_PATCH", rationale: "a vendor patch is recorded for this vulnerability (§84)" };
  }
  if (patch.conflictingFixedVersions) {
    return { action: "APPLY_VENDOR_MITIGATION", rationale: "sources disagree on the fixed version (§86) — apply the vendor mitigation and resolve the conflict before upgrading; no fix version is presented as definitive" };
  }
  if (patch.status === "MITIGATION_ONLY" && patch.mitigation) {
    return { action: "APPLY_VENDOR_MITIGATION", rationale: "no fixed version is recorded; apply the vendor/authoritative mitigation (§43)" };
  }
  if (input.reachability === "NOT_REACHABLE") {
    return { action: "REMOVE_UNUSED_COMPONENT", rationale: "component assessed NOT_REACHABLE on positive evidence — remove the unused component to eliminate the exposure class (§84)" };
  }
  if (patch.status === "NO_KNOWN_FIX") {
    return input.internetExposed || input.kevListed
      ? { action: "ISOLATE_OR_RESTRICT_EXPOSURE", rationale: "no known fix and the exposure is internet-facing and/or KEV-listed — isolate or restrict exposure and monitor (§84)" }
      : { action: "MONITOR_NO_FIX", rationale: "no known fix — monitor for a published fix and re-evaluate on intelligence change (§84)" };
  }
  return { action: "MONITOR_NO_FIX", rationale: "fix availability is not yet established — monitor; no version is recommended without a reliable source (§85)" };
}

// ------------------------------ blast radius (§79–§83) ------------------------------

export interface ComponentAppearance {
  componentId: string;
  componentName: string;
  /** Where the component appears: repository / image / build / binary. */
  appearanceKind: "REPOSITORY" | "IMAGE" | "BUILD" | "BINARY";
  appearanceId: string;
  appearanceLabel: string;
  dependencyScope: string; // DIRECT | TRANSITIVE | UNKNOWN (§81)
  dependencyPath?: string[]; // §82
  /** Workloads/assets the appearance deploys to, when the graph knows. */
  deployedTo: { kind: "WORKLOAD" | "ASSET"; id: string; label: string; internetExposed?: boolean }[];
}

export interface BlastRadius {
  cveId: string;
  /** §80: confirmed and potential are ALWAYS separate counts. */
  confirmed: { components: number; repositories: number; images: number; workloads: number; assets: number };
  potential: { components: number; repositories: number; images: number; workloads: number; assets: number };
  appearances: (ComponentAppearance & { affectedStatus: string })[];
  transitiveCount: number;
  directCount: number;
}

export function computeVulnerabilityBlastRadius(cveId: string, appearances: (ComponentAppearance & { affectedStatus: string })[]): BlastRadius {
  const tally = (list: typeof appearances) => {
    const comps = new Set<string>(); const repos = new Set<string>(); const images = new Set<string>();
    const workloads = new Set<string>(); const assets = new Set<string>();
    for (const a of list) {
      comps.add(a.componentId);
      if (a.appearanceKind === "REPOSITORY") repos.add(a.appearanceId);
      if (a.appearanceKind === "IMAGE") images.add(a.appearanceId);
      for (const d of a.deployedTo) {
        if (d.kind === "WORKLOAD") workloads.add(d.id); else assets.add(d.id);
      }
    }
    return { components: comps.size, repositories: repos.size, images: images.size, workloads: workloads.size, assets: assets.size };
  };
  const confirmedList = appearances.filter((a) => a.affectedStatus === "AFFECTED");
  const potentialList = appearances.filter((a) => a.affectedStatus === "POTENTIALLY_AFFECTED" || a.affectedStatus === "UNKNOWN");
  return {
    cveId,
    confirmed: tally(confirmedList),
    potential: tally(potentialList),
    appearances,
    transitiveCount: appearances.filter((a) => a.dependencyScope === "TRANSITIVE").length,
    directCount: appearances.filter((a) => a.dependencyScope === "DIRECT").length,
  };
}

/** §105: patch latency — defined formula, both timestamps required. */
export function patchLatencyHours(fixAvailableAt: string | undefined, remediatedAt: string | undefined): number | null {
  if (!fixAvailableAt || !remediatedAt) return null;
  const a = new Date(fixAvailableAt).getTime();
  const b = new Date(remediatedAt).getTime();
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.round(((b - a) / 3_600_000) * 10) / 10;
}

/** §106: the three ages are tracked separately — never conflated. */
export function vulnerabilityAges(input: { cvePublishedAt?: string; findingFirstSeenAt?: string; exposureFirstSeenAt?: string }, now: Date): {
  cveAgeDays: number | null; findingAgeDays: number | null; exposureAgeDays: number | null;
} {
  const days = (iso?: string) => {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    return Number.isFinite(t) ? Math.max(0, Math.floor((now.getTime() - t) / 86_400_000)) : null;
  };
  return { cveAgeDays: days(input.cvePublishedAt), findingAgeDays: days(input.findingFirstSeenAt), exposureAgeDays: days(input.exposureFirstSeenAt) };
}
