/**
 * Prompt 34 — Kubernetes RBAC analysis (§76/§77), admission posture
 * (§85) and Kubernetes attack-path candidates (§89).
 *
 * RBAC analysis is defensive over inventory DATA: wildcards,
 * cluster-admin-like bindings and dangerous verbs/resources become
 * risk records + graph edges. Privileges are never exercised — there
 * is no code path here that uses a role, harvests a token (§84) or
 * reads a Secret value (§83). Attack paths are analytical
 * candidates, never executed (§90).
 */
import type { CloudV2AttackPathCandidate } from "./types";

export interface K8sRoleRule {
  apiGroups?: string[];
  resources?: string[];
  verbs?: string[];
  resourceNames?: string[];
}

export interface K8sRoleRecord {
  kind: "Role" | "ClusterRole";
  namespace?: string | null;
  name: string;
  rules: K8sRoleRule[];
}

export interface K8sSubject {
  kind: "ServiceAccount" | "User" | "Group";
  name: string;
  namespace?: string | null;
}

export interface K8sRoleBindingRecord {
  kind: "RoleBinding" | "ClusterRoleBinding";
  namespace?: string | null;
  name: string;
  roleKind: "Role" | "ClusterRole";
  roleName: string;
  subjects: K8sSubject[];
}

export interface K8sRbacRisk {
  kind:
    | "WILDCARD_PERMISSIONS" | "CLUSTER_ADMIN_BINDING" | "DANGEROUS_VERB"
    | "SECRET_ACCESS" | "WORKLOAD_CREATION" | "ESCALATION_PRIVILEGE";
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  subject?: string;
  roleRef: string;
  bindingRef?: string;
  detail: string;
  evidence: string;
}

export interface K8sRbacGraphEdge {
  fromType: "SUBJECT" | "ROLE";
  fromRef: string;
  relationship: "BOUND_TO" | "GRANTS";
  toType: "ROLE" | "RESOURCE";
  toRef: string;
  evidence: string;
}

/** Verbs/resources whose grant is dangerous in the wrong hands (§76). */
export const DANGEROUS_K8S_VERBS = ["impersonate", "escalate", "bind", "approve"] as const;
export const DANGEROUS_K8S_RESOURCES = ["secrets", "pods/exec", "serviceaccounts/token", "clusterroles", "roles"] as const;

function roleRef(role: K8sRoleRecord): string {
  return role.kind === "ClusterRole" ? `clusterrole/${role.name}` : `role/${role.namespace ?? "default"}/${role.name}`;
}
function subjectRef(s: K8sSubject): string {
  return s.kind === "ServiceAccount" ? `serviceaccount/${s.namespace ?? "default"}/${s.name}` : `${s.kind.toLowerCase()}/${s.name}`;
}
function bindingRef(b: K8sRoleBindingRecord): string {
  return b.kind === "ClusterRoleBinding" ? `clusterrolebinding/${b.name}` : `rolebinding/${b.namespace ?? "default"}/${b.name}`;
}

function ruleGrantsWildcard(rule: K8sRoleRule): boolean {
  return (rule.verbs ?? []).includes("*") || (rule.resources ?? []).includes("*");
}
function isClusterAdminLike(role: K8sRoleRecord): boolean {
  if (role.name === "cluster-admin") return true;
  return role.rules.some((r) => ruleGrantsWildcard(r) && (r.apiGroups ?? []).includes("*") || (r.verbs ?? []).includes("*") && (r.resources ?? []).includes("*"));
}

/**
 * KubernetesRbacAnalysisService core (§76/§77): risks + the
 * SUBJECT → ROLE → PERMISSION → RESOURCE graph. A controlled
 * wildcard role yields an RBAC risk finding — and nothing else: no
 * privilege is used, ever (§152).
 */
export function analyzeKubernetesRbac(
  roles: K8sRoleRecord[],
  bindings: K8sRoleBindingRecord[],
): { risks: K8sRbacRisk[]; edges: K8sRbacGraphEdge[] } {
  const risks: K8sRbacRisk[] = [];
  const edges: K8sRbacGraphEdge[] = [];
  const roleByRef = new Map(roles.map((r) => [roleRef(r), r]));
  const roleByName = new Map(roles.map((r) => [`${r.kind}/${r.name}`, r]));

  for (const role of roles) {
    const ref = roleRef(role);
    for (const rule of role.rules) {
      const verbs = rule.verbs ?? [];
      const resources = rule.resources ?? [];
      if (ruleGrantsWildcard(rule)) {
        risks.push({
          kind: "WILDCARD_PERMISSIONS", severity: "HIGH", roleRef: ref,
          detail: `Role grants wildcard ${verbs.includes("*") ? "verbs" : "resources"} — overly broad permission set (§76).`,
          evidence: `verbs=[${verbs.join(",")}] resources=[${resources.join(",")}]`,
        });
      }
      for (const verb of DANGEROUS_K8S_VERBS) {
        if (verbs.includes(verb)) {
          risks.push({
            kind: verb === "impersonate" || verb === "escalate" ? "ESCALATION_PRIVILEGE" : "DANGEROUS_VERB",
            severity: "HIGH", roleRef: ref,
            detail: `Role grants the dangerous verb "${verb}" (§76).`,
            evidence: `verb=${verb} resources=[${resources.join(",")}]`,
          });
        }
      }
      if (resources.includes("secrets") && verbs.some((v) => ["get", "list", "watch", "*"].includes(v))) {
        risks.push({
          kind: "SECRET_ACCESS", severity: "HIGH", roleRef: ref,
          detail: "Role can read Secrets (metadata analysis only — the platform never retrieves Secret values, §83).",
          evidence: `resources=[secrets] verbs=[${verbs.join(",")}]`,
        });
      }
      if ((resources.includes("pods") || resources.includes("*")) && verbs.some((v) => ["create", "*"].includes(v))) {
        risks.push({
          kind: "WORKLOAD_CREATION", severity: "MEDIUM", roleRef: ref,
          detail: "Role can create workloads — combined with a privileged image this is a privilege path (§76).",
          evidence: `resources=[${resources.join(",")}] verbs=[${verbs.join(",")}]`,
        });
      }
      for (const resource of resources) {
        edges.push({ fromType: "ROLE", fromRef: ref, relationship: "GRANTS", toType: "RESOURCE", toRef: resource, evidence: `verbs=[${verbs.join(",")}] (§77)` });
      }
    }
  }

  for (const binding of bindings) {
    const bRef = bindingRef(binding);
    const role = roleByName.get(`${binding.roleKind}/${binding.roleName}`) ?? roleByRef.get(binding.roleKind === "ClusterRole" ? `clusterrole/${binding.roleName}` : `role/${binding.namespace ?? "default"}/${binding.roleName}`);
    for (const subject of binding.subjects) {
      const sRef = subjectRef(subject);
      edges.push({ fromType: "SUBJECT", fromRef: sRef, relationship: "BOUND_TO", toType: "ROLE", toRef: role ? roleRef(role) : `${binding.roleKind.toLowerCase()}/${binding.roleName}`, evidence: `binding ${bRef} (§77)` });
      if (role && isClusterAdminLike(role)) {
        risks.push({
          kind: "CLUSTER_ADMIN_BINDING", severity: "CRITICAL", subject: sRef, roleRef: roleRef(role), bindingRef: bRef,
          detail: `Subject ${sRef} is bound to cluster-admin-like role ${role.name} (§76). Recorded as a finding — the privilege is never used (§152).`,
          evidence: `binding=${bRef} role=${role.name}`,
        });
      }
    }
  }
  return { risks, edges };
}

/* --------------------------- Admission (§85) --------------------------- */

export interface AdmissionObservation {
  kind: "PSA_NOT_ENFORCED" | "PSA_BASELINE_ONLY" | "NO_POLICY_ENGINE" | "IMAGE_POLICY_ABSENT" | "ADMISSION_OK";
  severity: "MEDIUM" | "LOW" | "INFORMATIONAL";
  detail: string;
}

/** §85: admission posture from OBSERVABLE configuration metadata —
 *  Pod Security Admission levels, policy engines, image policies.
 *  Absence is reported in context, never assumed to be a breach. */
export function analyzeAdmissionPosture(input: {
  psaEnforceLevels?: Record<string, string>; // namespace → enforce level
  policyEngines?: string[];
  imagePolicyPresent?: boolean;
}): AdmissionObservation[] {
  const out: AdmissionObservation[] = [];
  const levels = Object.values(input.psaEnforceLevels ?? {});
  if (levels.length === 0) {
    out.push({ kind: "PSA_NOT_ENFORCED", severity: "MEDIUM", detail: "No Pod Security Admission enforce labels observed on any namespace (§85)." });
  } else if (levels.every((l) => l === "privileged")) {
    out.push({ kind: "PSA_NOT_ENFORCED", severity: "MEDIUM", detail: "Pod Security Admission is set to \"privileged\" everywhere observed — effectively unenforced (§85)." });
  } else if (!levels.some((l) => l === "restricted" || l === "baseline")) {
    out.push({ kind: "PSA_BASELINE_ONLY", severity: "LOW", detail: "Pod Security Admission observed only at audit/warn levels (§85)." });
  }
  if ((input.policyEngines ?? []).length === 0) {
    out.push({ kind: "NO_POLICY_ENGINE", severity: "LOW", detail: "No admission policy engine (Kyverno/Gatekeeper/PSA-only) observed in cluster metadata (§85)." });
  }
  if (input.imagePolicyPresent === false) {
    out.push({ kind: "IMAGE_POLICY_ABSENT", severity: "LOW", detail: "No image admission policy observed — unsigned/unapproved images are not blocked at admission (§85)." });
  }
  if (out.length === 0) out.push({ kind: "ADMISSION_OK", severity: "INFORMATIONAL", detail: "Admission controls observed in cluster metadata (§85)." });
  return out;
}

/* --------------------- Attack-path candidates (§89) --------------------- */

export interface K8sWorkloadFacts {
  namespace: string;
  kind: string;
  name: string;
  serviceAccount?: string;
  exposure: string; // PUBLIC_INTERNET | EXTERNAL_NETWORK | CLUSTER_INTERNAL | ...
  privileged?: boolean;
  criticalVulnerabilities?: number;
}

/**
 * §89: Internet Ingress → Vulnerable Workload → Overprivileged
 * Service Account → Sensitive Namespace/Resource. Analytical only —
 * never executed (§90).
 */
export function buildKubernetesAttackPathCandidates(input: {
  workloads: K8sWorkloadFacts[];
  rbacRisks: K8sRbacRisk[];
  sensitiveNamespaces?: string[];
}): CloudV2AttackPathCandidate[] {
  const candidates: CloudV2AttackPathCandidate[] = [];
  const sensitive = new Set(input.sensitiveNamespaces ?? ["kube-system", "production-secrets", "payments"]);
  const overprivilegedSubjects = new Set(
    input.rbacRisks.filter((r) => r.kind === "CLUSTER_ADMIN_BINDING" || r.kind === "WILDCARD_PERMISSIONS")
      .map((r) => r.subject).filter((s): s is string => Boolean(s)),
  );
  for (const w of input.workloads) {
    if (w.exposure !== "PUBLIC_INTERNET") continue;
    if (!w.serviceAccount) continue;
    const saRef = `serviceaccount/${w.namespace}/${w.serviceAccount}`;
    if (!overprivilegedSubjects.has(saRef)) continue;
    const targetNs = [...sensitive].find((ns) => ns !== w.namespace) ?? "kube-system";
    candidates.push({
      title: `Internet ingress → workload ${w.namespace}/${w.name} → overprivileged SA ${w.serviceAccount} → sensitive namespace ${targetNs}`,
      domain: "KUBERNETES",
      steps: [
        { kind: "INTERNET_INGRESS", ref: `${w.namespace}/${w.name}`, label: `Public workload ${w.name}`, evidence: "OBSERVED" },
        { kind: "WORKLOAD", ref: `${w.kind}/${w.namespace}/${w.name}`, label: `${w.kind} ${w.name}${(w.criticalVulnerabilities ?? 0) > 0 ? ` (${w.criticalVulnerabilities} critical vulnerabilities)` : ""}`, evidence: "OBSERVED" },
        { kind: "SERVICE_ACCOUNT", ref: saRef, label: `Overprivileged service account ${w.serviceAccount}`, evidence: "OBSERVED" },
        { kind: "SENSITIVE_NAMESPACE", ref: targetNs, label: `Sensitive namespace ${targetNs}`, evidence: "INFERRED" },
      ],
      confidence: (w.criticalVulnerabilities ?? 0) > 0 ? "HIGH" : "MEDIUM",
      executed: false,
    });
  }
  return candidates;
}
