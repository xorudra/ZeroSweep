/**
 * Prompt 37 §11: deterministic triage-queue prioritization.
 *
 * The queue order is computed from stored finding facts only — risk,
 * severity, KEV, EPSS, internet exposure, asset criticality, runtime
 * evidence, age, SLA pressure and verification confidence (§11). The
 * score is an ordering aid for analysts; it never changes a finding's
 * risk score (Risk Engine V3 owns that) and every factor is returned
 * so the ordering is explainable in the UI and in audits.
 */
export interface TriageFindingInput {
  id: string;
  severity: string; // CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
  riskScore?: number | null;
  kevListed?: boolean;
  epssScore?: number | null;
  internetExposed?: boolean;
  assetCriticality?: string | null; // CRITICAL | HIGH | MEDIUM | LOW
  runtimeEvidence?: boolean; // dynamically confirmed / runtime-correlated
  createdAt: Date | string;
  dueAt?: Date | string | null;
  verificationStatus?: string | null; // UNVERIFIED | LIKELY | CONFIRMED | REJECTED
  lifecycleStatus: string;
}

export interface TriageScore {
  findingId: string;
  score: number; // 0..100, deterministic
  band: "P0" | "P1" | "P2" | "P3" | "P4";
  factors: { key: string; points: number; note: string }[];
}

const SEVERITY_POINTS: Record<string, number> = { CRITICAL: 30, HIGH: 22, MEDIUM: 14, LOW: 7, INFORMATIONAL: 2 };
const CRITICALITY_POINTS: Record<string, number> = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };

function daysBetween(from: Date, to: Date): number {
  return Math.max(0, Math.floor((to.getTime() - from.getTime()) / 86_400_000));
}

/** §11: closed/terminal findings never enter the triage queue. */
const QUEUE_EXCLUDED = new Set(["RESOLVED", "FALSE_POSITIVE", "DUPLICATE"]);

export function triageScore(finding: TriageFindingInput, now: Date): TriageScore {
  const factors: TriageScore["factors"] = [];
  const add = (key: string, points: number, note: string) => { if (points !== 0) factors.push({ key, points, note }); };

  add("severity", SEVERITY_POINTS[finding.severity] ?? 2, `severity ${finding.severity}`);
  if (typeof finding.riskScore === "number") {
    add("risk", Math.round(Math.min(20, Math.max(0, finding.riskScore / 5))), `risk score ${finding.riskScore} (Risk Engine V3)`);
  }
  if (finding.kevListed) add("kev", 15, "listed in CISA KEV");
  if (typeof finding.epssScore === "number") {
    add("epss", Math.round(finding.epssScore * 10), `EPSS ${finding.epssScore}`);
  }
  if (finding.internetExposed) add("exposure", 8, "internet-exposed asset");
  if (finding.assetCriticality) {
    add("criticality", CRITICALITY_POINTS[finding.assetCriticality] ?? 0, `asset criticality ${finding.assetCriticality}`);
  }
  if (finding.runtimeEvidence) add("runtime", 6, "runtime/dynamic evidence present");
  const ageDays = daysBetween(new Date(finding.createdAt), now);
  add("age", Math.min(8, Math.floor(ageDays / 14)), `open for ${ageDays} day(s)`);
  if (finding.dueAt) {
    const due = new Date(finding.dueAt);
    if (due.getTime() < now.getTime()) add("sla", 10, "SLA overdue");
    else if (due.getTime() - now.getTime() < 48 * 3_600_000) add("sla", 5, "SLA due within 48h");
  }
  if (finding.verificationStatus === "CONFIRMED") add("confidence", 4, "verification CONFIRMED");
  else if (finding.verificationStatus === "LIKELY") add("confidence", 2, "verification LIKELY");

  const score = Math.min(100, factors.reduce((sum, f) => sum + f.points, 0));
  const band: TriageScore["band"] = score >= 70 ? "P0" : score >= 52 ? "P1" : score >= 36 ? "P2" : score >= 20 ? "P3" : "P4";
  return { findingId: finding.id, score, band, factors };
}

/** §11/§12: the queue — scored, deterministically ordered (score desc,
 *  then oldest first, then id for stability). REJECTED-verification and
 *  terminal findings are excluded. */
export function buildTriageQueue(findings: TriageFindingInput[], now: Date): TriageScore[] {
  return findings
    .filter((f) => !QUEUE_EXCLUDED.has(f.lifecycleStatus) && f.verificationStatus !== "REJECTED")
    .map((f) => triageScore(f, now))
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      const fa = findings.find((f) => f.id === a.findingId)!;
      const fb = findings.find((f) => f.id === b.findingId)!;
      const byAge = new Date(fa.createdAt).getTime() - new Date(fb.createdAt).getTime();
      return byAge !== 0 ? byAge : a.findingId.localeCompare(b.findingId);
    });
}
