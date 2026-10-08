import type { AttackMapping } from "./templates";

/**
 * Detection coverage + health (Prompt 28 §112–§116). Coverage means
 * DETECTION-RULE coverage (§113): a technique is "covered" when an
 * ACTIVE, tested rule maps to it. Coverage never implies prevention.
 */

export interface CoverageRule {
  id: string;
  status: string;
  tested: boolean;
  attack: AttackMapping[];
  dataSources: string[];
  lastEvaluatedAt?: string | null;
  evaluationFailures: number;
  matchCount: number;
  falsePositiveCount: number;
  triagedCount: number;
}

export interface TechniqueCoverage {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  activeRules: number;
  testedRules: number;
  covered: boolean;
}

export function computeDetectionCoverage(rules: CoverageRule[]): {
  techniques: TechniqueCoverage[];
  coveredTechniques: number;
  totalTechniques: number;
  note: string;
} {
  const byTechnique = new Map<string, TechniqueCoverage>();
  for (const rule of rules) {
    for (const m of rule.attack) {
      const key = m.subTechniqueId ?? m.techniqueId;
      const entry = byTechnique.get(key) ?? {
        techniqueId: key, techniqueName: m.techniqueName, tactic: m.tactic,
        activeRules: 0, testedRules: 0, covered: false,
      };
      if (rule.status === "ACTIVE") {
        entry.activeRules++;
        if (rule.tested) entry.testedRules++;
      }
      entry.covered = entry.activeRules > 0 && entry.testedRules > 0;
      byTechnique.set(key, entry);
    }
  }
  const techniques = [...byTechnique.values()].sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));
  return {
    techniques,
    coveredTechniques: techniques.filter((t) => t.covered).length,
    totalTechniques: techniques.length,
    note: "Coverage = an ACTIVE, tested detection rule maps to the technique. It describes detection-rule coverage only and does not imply attacks are prevented (§113).",
  };
}

export interface DetectionHealth {
  rulesWithNoDataSource: string[];
  noisyRules: Array<{ ruleId: string; falsePositiveRate: number | null }>;
  failingRules: Array<{ ruleId: string; evaluationFailures: number }>;
  disabledRules: number;
  staleRules: string[];
}

export function computeDetectionHealth(rules: CoverageRule[], now: Date, staleAfterHours = 24): DetectionHealth {
  const staleCutoff = now.getTime() - staleAfterHours * 3600 * 1000;
  return {
    rulesWithNoDataSource: rules.filter((r) => r.status === "ACTIVE" && r.dataSources.length === 0).map((r) => r.id),
    noisyRules: rules.map((r) => ({
      ruleId: r.id,
      falsePositiveRate: r.triagedCount > 0 ? Math.round((r.falsePositiveCount / r.triagedCount) * 1000) / 1000 : null,
    })).filter((r) => r.falsePositiveRate !== null && r.falsePositiveRate >= 0.5),
    failingRules: rules.filter((r) => r.evaluationFailures > 0).map((r) => ({ ruleId: r.id, evaluationFailures: r.evaluationFailures })),
    disabledRules: rules.filter((r) => r.status === "DISABLED").length,
    staleRules: rules.filter((r) => r.status === "ACTIVE" && (!r.lastEvaluatedAt || new Date(r.lastEvaluatedAt).getTime() < staleCutoff)).map((r) => r.id),
  };
}
