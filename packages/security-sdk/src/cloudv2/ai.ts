/**
 * Prompt 34 — AI Cloud Copilot guardrails (§135/§136), deterministic
 * natural-language queries (§137) and the V2 report catalog (§133).
 *
 * The copilot summarizes and explains RECORDED cloud/container/
 * Kubernetes evidence. It cannot change cloud resources, create IAM
 * privilege, retrieve secrets, execute attack paths, disable
 * logging, open security groups, modify workloads or bypass
 * approval (§136). Those refusals are STRUCTURAL — matched before
 * any planning — so §160's request ("Make all buckets private and
 * remove admin roles") yields a remediation PLAN, never an action.
 *
 * Natural language maps to DETERMINISTIC query plans (§137): the
 * same sentence always yields the same typed plan, executed by the
 * API over stored records only.
 */
import type { ReportType } from "../unified/reporting";

const FORBIDDEN_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /make .* (private|public)|remove .* (role|admin|permission)|delete .* (bucket|resource|pod|workload|role)|disable .* log|open .* security group|create .* (iam|role|policy|privilege)|grant .* (access|admin|permission)/i, reason: "The copilot cannot change cloud resources or IAM (§136) — it produces an evidence-backed remediation plan for a human to execute through Prompt 31 instead." },
  { pattern: /escalat|privilege escalation|assume .* role .* (to|and) (access|read|dump)|lateral/i, reason: "Privilege escalation and lateral movement are forbidden (§136/§166)." },
  { pattern: /(retrieve|dump|show|reveal|get|read|print)\b[^.]*\b(secret|credential|password|token|kubeconfig|private key)/i, reason: "The copilot cannot retrieve secrets or kubeconfig content (§136/§72) — only secret REFERENCE names and metadata exist in its context." },
  { pattern: /execute .* (attack|path|exploit)|run .* exploit|attack path .* execute/i, reason: "Attack paths are analytical models — they are never executed (§33/§90/§136)." },
  { pattern: /restart|kill|scale .* (workload|pod|deployment)|patch .* cluster|modify .* workload/i, reason: "The copilot cannot modify or restart Kubernetes workloads (§96/§136)." },
  { pattern: /bypass|skip .* approval|approve .* (myself|automatically)/i, reason: "The copilot cannot bypass approval gates (§136)." },
];

export interface CloudAiVerdict { allowed: boolean; reason?: string }

/** Every copilot request passes this gate FIRST (§136). */
export function screenCloudAiRequest(text: string): CloudAiVerdict {
  for (const { pattern, reason } of FORBIDDEN_PATTERNS) {
    if (pattern.test(text)) return { allowed: false, reason };
  }
  return { allowed: true };
}

export type CloudNlQueryKind =
  | "PUBLIC_PRODUCTION_DATABASES"
  | "KEV_RUNNING_CONTAINERS"
  | "PRIVILEGED_WORKLOAD_CLUSTERS"
  | "BROAD_PERMISSION_IDENTITIES"
  | "INTERNET_WORKLOADS_CRITICAL_VULNS"
  | "PUBLIC_STORAGE"
  | "UNSUPPORTED";

export interface CloudNlQueryPlan {
  kind: CloudNlQueryKind;
  rationale: string;
  /** The plan reads stored records only; it executes nothing (§137). */
  executes: false;
  filters: Record<string, string | boolean>;
}

const NL_RULES: Array<{ pattern: RegExp; kind: CloudNlQueryKind; rationale: string; filters: Record<string, string | boolean> }> = [
  { pattern: /public .*production database|production database.*public/i, kind: "PUBLIC_PRODUCTION_DATABASES", rationale: "\"Show public production databases\" → cloud resources of database type, PUBLIC exposure, PRODUCTION environment (§137).", filters: { domain: "CLOUD", resourceClass: "DATABASE", exposure: "PUBLIC", environment: "PRODUCTION" } },
  { pattern: /kev .* (running|deployed) container|running container.*kev/i, kind: "KEV_RUNNING_CONTAINERS", rationale: "\"Show KEV vulnerabilities in running containers\" → KEV findings on images correlated to workloads (§137).", filters: { domain: "CONTAINER", kev: true, deployed: true } },
  { pattern: /clusters? .* privileged workload|privileged workload.*cluster/i, kind: "PRIVILEGED_WORKLOAD_CLUSTERS", rationale: "\"Which clusters have privileged workloads?\" → clusters with privileged containers in workload security context (§137).", filters: { domain: "KUBERNETES", privilegedWorkloads: true } },
  { pattern: /identit.* broad permission|broad permission.*identit|overprivileged identit/i, kind: "BROAD_PERMISSION_IDENTITIES", rationale: "\"Which identities have broad permissions?\" → IAM posture signals of kind OVERLY_BROAD_PERMISSIONS (§137).", filters: { domain: "CLOUD", iamSignal: "OVERLY_BROAD_PERMISSIONS" } },
  { pattern: /internet-facing workload.* critical|workload.*internet.*critical/i, kind: "INTERNET_WORKLOADS_CRITICAL_VULNS", rationale: "\"Show internet-facing workloads with critical vulnerabilities\" → PUBLIC_INTERNET workloads whose images carry CRITICAL findings (§137).", filters: { domain: "KUBERNETES", exposure: "PUBLIC_INTERNET", severity: "CRITICAL" } },
  { pattern: /public (storage|bucket)/i, kind: "PUBLIC_STORAGE", rationale: "Public storage language → storage resources with PUBLIC exposure (§137).", filters: { domain: "CLOUD", resourceClass: "STORAGE", exposure: "PUBLIC" } },
];

/** §137: natural language → deterministic typed query plan, or a
 *  §136 refusal when the request asks the copilot to ACT. */
export function planCloudNlQuery(text: string): { plan?: CloudNlQueryPlan; refusal?: string } {
  const screen = screenCloudAiRequest(text);
  if (!screen.allowed) return { refusal: screen.reason };
  for (const rule of NL_RULES) {
    if (rule.pattern.test(text)) {
      return { plan: { kind: rule.kind, rationale: rule.rationale, executes: false, filters: rule.filters } };
    }
  }
  return {
    plan: {
      kind: "UNSUPPORTED", rationale: "No deterministic V2 query matches this phrasing — rephrase using the governed query shapes (§137).", executes: false, filters: {},
    },
  };
}

/**
 * §135/§160: produce the copilot's answer for a change request — a
 * remediation PLAN (steps for a human, routed through Prompt 31),
 * with `executed: false`. The platform takes no provider action.
 */
export function cloudRemediationPlanOnlyAnswer(request: string, findings: Array<{ title: string; remediation?: string }>): {
  executed: false;
  answer: string;
  planSteps: string[];
} {
  const steps = findings.slice(0, 10).map((f, i) => `${i + 1}. ${f.title}${f.remediation ? ` — guidance: ${f.remediation}` : ""}`);
  return {
    executed: false,
    answer: `I can't make that change — the copilot never modifies cloud resources, IAM or workloads (§136/§160). Here is the evidence-backed remediation plan for a human to execute and verify through the remediation workflow (Prompt 31):`,
    planSteps: steps.length ? steps : ["1. No recorded findings match this request — run an assessment first; nothing was changed."],
  };
}

/* ------------------------------ Reports (§133) ------------------------------ */

export interface CloudV2ReportDefinition {
  key: string;
  title: string;
  /** Maps onto the Prompt 20 reporting engine — no parallel system. */
  reportType: ReportType;
  domains: string[];
}

/** §133: the V2 report catalog, rendered by the existing P20 engine
 *  from immutable snapshots with §134 content (scope, authorization,
 *  tools/versions, coverage, permission limitations, findings, risk,
 *  attack-path context, compliance mappings, remediation,
 *  verification) and the no-certification rule (§102). */
export const CLOUD_V2_REPORTS: CloudV2ReportDefinition[] = [
  { key: "CLOUD_SECURITY_POSTURE", title: "Cloud Security Posture Report", reportType: "CLOUD", domains: ["CLOUD"] },
  { key: "CLOUD_IAM_RISK", title: "Cloud IAM Risk Report", reportType: "CLOUD", domains: ["CLOUD"] },
  { key: "CLOUD_EXPOSURE", title: "Cloud Exposure Report", reportType: "CLOUD", domains: ["CLOUD"] },
  { key: "CONTAINER_VULNERABILITY", title: "Container Vulnerability Report", reportType: "CONTAINER_KUBERNETES", domains: ["CONTAINER"] },
  { key: "SBOM_SECURITY", title: "SBOM Security Report", reportType: "CONTAINER_KUBERNETES", domains: ["CONTAINER", "SAST", "SCA"] },
  { key: "KUBERNETES_ASSESSMENT", title: "Kubernetes Security Assessment", reportType: "CONTAINER_KUBERNETES", domains: ["KUBERNETES"] },
  { key: "KUBERNETES_CIS_BENCHMARK", title: "Kubernetes CIS Benchmark Report", reportType: "CONTAINER_KUBERNETES", domains: ["KUBERNETES"] },
  { key: "CLOUD_CONTAINER_K8S_EXECUTIVE", title: "Cloud/Container/Kubernetes Executive Report", reportType: "EXECUTIVE", domains: ["CLOUD", "CONTAINER", "KUBERNETES"] },
];

/** §101/§102: compliance mapping statement attached to V2 reports —
 *  mappings are evidence for GRC controls; a tool pass is never a
 *  certification claim. */
export const CLOUD_V2_NO_CERTIFICATION_STATEMENT =
  "Benchmark and framework results in this report are assessment evidence mapped to CIS, NIST, ISO 27001, SOC 2 and PCI DSS controls where evidence supports the mapping. A passing tool check is not a compliance certification (§102).";
