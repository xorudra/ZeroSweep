import { sha256Hex } from "../identity/crypto";

/**
 * Cross-domain correlation (Prompt 27 §73–§80).
 *
 * Rules are TYPED DECLARATIVE conditions over a joined subject —
 * data, never code (§75/§148). Signals are evidence-backed, carry a
 * confidence derived from evidence completeness (§77), dedupe by a
 * stable fingerprint (§78), and NEVER overwrite canonical finding
 * severity (§80): they add contextual risk and workflow candidates.
 */

export interface CorrelationCondition { field: string; op: "eq" | "neq" | "gte" | "lte" | "in" | "truthy" | "falsy"; value?: unknown }

export interface CorrelationRuleDef {
  name: string;
  description: string;
  inputTypes: string[];
  conditions: CorrelationCondition[];
  severity: string;
  outputType: string;
  version: number;
}

/** The joined view a rule evaluates: finding + its asset + repository + control context. */
export interface CorrelationSubject {
  findingId?: string | null;
  assetId?: string | null;
  resourceType?: string | null;
  resourceId?: string | null;
  findingSeverity?: string | null;
  findingStatus?: string | null;
  lifecycleStatus?: string | null;
  verificationStatus?: string | null;
  kevListed?: boolean;
  epssScore?: number | null;
  riskScore?: number | null;
  category?: string | null;
  sourceDomain?: string | null;
  cve?: string | null;
  cwe?: string | null;
  assetCriticality?: string | null;
  internetExposed?: boolean;
  repositoryVisibility?: string | null;
  privileged?: boolean;
  mfaEnrolled?: boolean;
  controlState?: string | null;
  workloadPublic?: boolean;
}

export const BUILTIN_CORRELATION_RULES: CorrelationRuleDef[] = [
  {
    name: "Internet-exposed KEV finding",
    description: "A KEV-listed finding on an internet-facing asset.",
    inputTypes: ["FINDING", "ASSET"],
    conditions: [
      { field: "kevListed", op: "truthy" },
      { field: "internetExposed", op: "truthy" },
    ],
    severity: "CRITICAL", outputType: "INTERNET_EXPOSED_KEV", version: 1,
  },
  {
    name: "Critical asset with verified critical finding",
    description: "A CONFIRMED critical finding on a CRITICAL-criticality asset.",
    inputTypes: ["FINDING", "ASSET"],
    conditions: [
      { field: "assetCriticality", op: "eq", value: "CRITICAL" },
      { field: "findingSeverity", op: "eq", value: "CRITICAL" },
      { field: "verificationStatus", op: "eq", value: "CONFIRMED" },
    ],
    severity: "CRITICAL", outputType: "CRITICAL_ASSET_CRITICAL_FINDING", version: 1,
  },
  {
    name: "Secret in public repository",
    description: "A secret-category finding whose repository is public.",
    inputTypes: ["FINDING", "REPOSITORY"],
    conditions: [
      { field: "category", op: "eq", value: "SECRET" },
      { field: "repositoryVisibility", op: "eq", value: "PUBLIC" },
    ],
    severity: "HIGH", outputType: "SECRET_PLUS_PUBLIC_REPOSITORY", version: 1,
  },
  {
    name: "Vulnerable image in public workload",
    description: "A container-domain finding on a publicly exposed workload.",
    inputTypes: ["FINDING", "WORKLOAD"],
    conditions: [
      { field: "sourceDomain", op: "eq", value: "CONTAINER" },
      { field: "workloadPublic", op: "truthy" },
    ],
    severity: "HIGH", outputType: "VULNERABLE_IMAGE_IN_PUBLIC_WORKLOAD", version: 1,
  },
  {
    name: "Privileged identity with weak MFA",
    description: "A privileged identity without MFA enrollment.",
    inputTypes: ["IDENTITY"],
    conditions: [
      { field: "privileged", op: "truthy" },
      { field: "mfaEnrolled", op: "falsy" },
    ],
    severity: "HIGH", outputType: "PRIVILEGED_IDENTITY_WITH_WEAK_MFA", version: 1,
  },
  {
    name: "Failed control with active critical finding",
    description: "A FAIL control evaluation alongside an open critical finding.",
    inputTypes: ["CONTROL", "FINDING"],
    conditions: [
      { field: "controlState", op: "eq", value: "FAIL" },
      { field: "findingSeverity", op: "eq", value: "CRITICAL" },
    ],
    severity: "HIGH", outputType: "FAILED_CONTROL_WITH_ACTIVE_CRITICAL_FINDING", version: 1,
  },
];

function evalCondition(subject: CorrelationSubject, c: CorrelationCondition): boolean {
  const v = (subject as unknown as Record<string, unknown>)[c.field];
  switch (c.op) {
    case "truthy": return v === true || (typeof v === "string" && v.length > 0) || (typeof v === "number" && v > 0);
    case "falsy": return v === false || v === null || v === undefined;
    case "eq": return v === c.value;
    case "neq": return v !== c.value;
    case "gte": return typeof v === "number" && typeof c.value === "number" && v >= c.value;
    case "lte": return typeof v === "number" && typeof c.value === "number" && v <= c.value;
    case "in": return Array.isArray(c.value) && (c.value as unknown[]).includes(v);
  }
}

/**
 * §77 confidence from evidence completeness: how many of the
 * expected evidence anchors are actually present (finding, asset,
 * verification state, exposure fact). Verified + complete = HIGH.
 */
export function signalConfidence(subject: CorrelationSubject): "LOW" | "MEDIUM" | "HIGH" {
  let anchors = 0;
  let present = 0;
  const check = (v: unknown) => { anchors++; if (v !== null && v !== undefined && v !== "") present++; };
  check(subject.findingId ?? subject.resourceId);
  check(subject.assetId);
  check(subject.verificationStatus);
  check(subject.internetExposed === undefined ? null : String(subject.internetExposed));
  if (anchors === 0) return "LOW";
  const ratio = present / anchors;
  if (ratio >= 1 && subject.verificationStatus === "CONFIRMED") return "HIGH";
  if (ratio >= 0.75) return "MEDIUM";
  if (ratio >= 0.5) return "MEDIUM";
  return "LOW";
}

export interface CorrelationMatch {
  rule: CorrelationRuleDef;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  fingerprint: string;
  evidence: Record<string, unknown>;
}

/** Evaluate one subject against rules. Pure + deterministic. */
export function evaluateCorrelation(subject: CorrelationSubject, workspaceId: string, rules: readonly CorrelationRuleDef[] = BUILTIN_CORRELATION_RULES): CorrelationMatch[] {
  const out: CorrelationMatch[] = [];
  for (const rule of rules) {
    if (!rule.conditions.every((c) => evalCondition(subject, c))) continue;
    const confidence = signalConfidence(subject);
    const fingerprint = sha256Hex([
      workspaceId, rule.outputType, subject.findingId ?? "", subject.assetId ?? "", subject.resourceId ?? "",
    ].join("|"));
    out.push({
      rule, confidence, fingerprint,
      evidence: {
        findingId: subject.findingId ?? null, assetId: subject.assetId ?? null,
        resourceType: subject.resourceType ?? null, resourceId: subject.resourceId ?? null,
        verificationStatus: subject.verificationStatus ?? null,
        internetExposed: subject.internetExposed ?? null,
        kevListed: subject.kevListed ?? null, cve: subject.cve ?? null,
        matchedConditions: rule.conditions.map((c) => `${c.field} ${c.op}${c.value !== undefined ? ` ${String(c.value)}` : ""}`),
      },
    });
  }
  return out;
}
