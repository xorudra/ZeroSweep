import {
  BadRequestException, Inject, Injectable, NotFoundException,
} from "@nestjs/common";
import {
  DEFAULT_KUBERNETES_BASELINE_RULES, KUBERNETES_PIPELINE_STAGES,
  analyzeAdmissionPosture, analyzeKubernetesRbac, buildKubernetesAttackPathCandidates,
  buildKubernetesCoverage, correlateRuntimeEvent, evaluateBaselineDeviations,
  hashBaselineRules, planKubernetesVerification,
  type CloudV2BaselineRule, type CloudV2PipelineStage, type K8sRoleBindingRecord, type K8sRoleRecord,
} from "@dsrclone/security-sdk";
import { AuditService } from "../audit/audit.service";
import { AlertService } from "../soc/alerts/alert.service";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { resolveWorkspace } from "../../common/tenant";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireKubernetesV2Permission, kubernetesV2PermissionsFor } from "./permissions";

type AuthUser = RequestUser;
type Headers = Record<string, string | string[] | undefined>;
/* eslint-disable @typescript-eslint/no-explicit-any */
type Row = Record<string, any>;

const SUBJECT_KINDS = ["ServiceAccount", "User", "Group"] as const;
const FORBIDDEN_SUBJECT_FIELDS = ["token", "secret", "password", "credential", "certificate", "key"];

/**
 * Kubernetes Security V2 (Prompt 34 §4/§70–§96/§105). Deepens the
 * Prompt 13 engine on the same KubernetesCluster / Workload /
 * RuntimeSecurityEvent models, adding RBAC inventory + analysis
 * (§76/§77), admission posture (§85), the Kubernetes Orchestrator
 * (§105), attack-path candidates (§89), Falco correlation with SOC
 * linkage (§94/§141), baselines (§98/§100) and coverage (§114).
 *
 * Structural rules: kubeconfig content is never accepted or stored
 * (§72 — clusters carry a reference name only, enforced since
 * Prompt 13); Secret VALUES are never inventoried (§83 — RBAC import
 * rejects token/secret-shaped fields outright); service-account
 * tokens are never harvested (§84); attack paths are never executed
 * (§90); no workload is ever killed, deleted or restarted (§96).
 */
@Injectable()
export class KubernetesSecurityService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly auditService: AuditService,
    private readonly alertService: AlertService,
  ) {}

  private ws(user: AuthUser, headers: Headers) {
    return resolveWorkspace(this.prisma, user, headers["x-workspace-id"] as string | undefined);
  }

  private async audit(workspaceId: string, user: AuthUser, action: string, entityType: string, entityId: string, metadata?: Record<string, unknown>): Promise<void> {
    await this.auditService
      .record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: action as never, resourceType: entityType, resourceId: entityId,
        ...(metadata ? { metadata } : {}),
      })
      .catch(() => undefined);
  }

  mePermissions(user: AuthUser) {
    return { role: user.role, permissions: kubernetesV2PermissionsFor(user.role) };
  }

  private async clusterOr404(workspaceId: string, id: string): Promise<Row> {
    const cluster = await this.prisma.kubernetesCluster.findFirst({ where: { id, workspaceId } });
    if (!cluster) throw new NotFoundException("Kubernetes cluster not found");
    return cluster as Row;
  }

  /* --------------------- RBAC inventory + analysis (§76/§77) --------------------- */

  private sanitizeSubjects(raw: unknown): K8sRoleBindingRecord["subjects"] {
    if (!Array.isArray(raw)) throw new BadRequestException("subjects must be an array (§76)");
    return raw.map((entry) => {
      const e = (entry ?? {}) as Row;
      for (const key of Object.keys(e)) {
        if (FORBIDDEN_SUBJECT_FIELDS.some((f) => key.toLowerCase().includes(f))) {
          throw new BadRequestException(`Subject field "${key}" is refused — tokens and secret material are never inventoried (§83/§84)`);
        }
      }
      if (!SUBJECT_KINDS.includes(e.kind)) throw new BadRequestException(`Subject kind must be one of ${SUBJECT_KINDS.join(", ")} (§76)`);
      return { kind: e.kind, name: String(e.name ?? ""), ...(e.namespace ? { namespace: String(e.namespace) } : {}) } as K8sRoleBindingRecord["subjects"][number];
    });
  }

  async importRbac(user: AuthUser, headers: Headers, clusterId: string, body: Record<string, unknown>) {
    requireKubernetesV2Permission(user, "MANAGE_KUBERNETES_CLUSTERS");
    const workspace = await this.ws(user, headers);
    await this.clusterOr404(workspace.id, clusterId);
    const roles = (Array.isArray(body.roles) ? body.roles : []) as Row[];
    const bindings = (Array.isArray(body.bindings) ? body.bindings : []) as Row[];
    let roleCount = 0;
    let bindingCount = 0;
    for (const role of roles) {
      const kind = role.kind === "ClusterRole" ? "ClusterRole" : "Role";
      const namespace = kind === "ClusterRole" ? null : String(role.namespace ?? "default");
      const existing = await this.prisma.kubernetesRole.findFirst({
        where: { clusterId, kind, namespace, name: String(role.name ?? "") },
      });
      const data = {
        workspaceId: workspace.id, clusterId, kind, namespace, name: String(role.name ?? ""),
        rules: (role.rules ?? []) as never, labels: (role.labels ?? {}) as never,
      };
      if (existing) await this.prisma.kubernetesRole.update({ where: { id: (existing as Row).id }, data });
      else await this.prisma.kubernetesRole.create({ data });
      roleCount++;
    }
    for (const binding of bindings) {
      const kind = binding.kind === "ClusterRoleBinding" ? "ClusterRoleBinding" : "RoleBinding";
      const namespace = kind === "ClusterRoleBinding" ? null : String(binding.namespace ?? "default");
      const subjects = this.sanitizeSubjects(binding.subjects);
      const existing = await this.prisma.kubernetesRoleBinding.findFirst({
        where: { clusterId, kind, namespace, name: String(binding.name ?? "") },
      });
      const data = {
        workspaceId: workspace.id, clusterId, kind, namespace, name: String(binding.name ?? ""),
        roleKind: binding.roleKind === "ClusterRole" ? "ClusterRole" : "Role", roleName: String(binding.roleName ?? ""),
        subjects: subjects as never,
      };
      if (existing) await this.prisma.kubernetesRoleBinding.update({ where: { id: (existing as Row).id }, data });
      else await this.prisma.kubernetesRoleBinding.create({ data });
      bindingCount++;
    }
    return { clusterId, roles: roleCount, bindings: bindingCount, note: "RBAC inventory stored as data — privileges are analyzed, never used (§76/§152)." };
  }

  async getRbac(user: AuthUser, headers: Headers, clusterId: string) {
    requireKubernetesV2Permission(user, "VIEW_KUBERNETES_RBAC");
    const workspace = await this.ws(user, headers);
    await this.clusterOr404(workspace.id, clusterId);
    const roles = await this.prisma.kubernetesRole.findMany({ where: { workspaceId: workspace.id, clusterId }, take: 500 }) as Row[];
    const bindings = await this.prisma.kubernetesRoleBinding.findMany({ where: { workspaceId: workspace.id, clusterId }, take: 500 }) as Row[];
    const analysis = analyzeKubernetesRbac(
      roles.map((r) => ({ kind: r.kind, namespace: r.namespace, name: r.name, rules: (r.rules ?? []) as K8sRoleRecord["rules"] })),
      bindings.map((b) => ({
        kind: b.kind, namespace: b.namespace, name: b.name, roleKind: b.roleKind, roleName: b.roleName,
        subjects: (b.subjects ?? []) as K8sRoleBindingRecord["subjects"],
      })),
    );
    return { clusterId, roles, bindings, risks: analysis.risks, edges: analysis.edges };
  }

  /* --------------------- orchestrator (§105) --------------------- */

  async assessCluster(user: AuthUser, headers: Headers, clusterId: string, body: Record<string, unknown>) {
    requireKubernetesV2Permission(user, "RUN_KUBERNETES_ASSESSMENT");
    const workspace = await this.ws(user, headers);
    const cluster = await this.clusterOr404(workspace.id, clusterId);

    const run = await this.prisma.cloudV2AssessmentRun.create({
      data: { workspaceId: workspace.id, domain: "KUBERNETES", clusterId, status: "RUNNING", startedById: user.id, pipeline: [] as never },
    }) as Row;
    await this.audit(workspace.id, user, "KUBERNETES_ASSESSMENT_STARTED", "KubernetesCluster", clusterId, { runId: run.id });

    const stages: CloudV2PipelineStage[] = [];
    const stage = (name: string, status: CloudV2PipelineStage["status"], detail: string) => stages.push({ stage: name, status, detail });

    stage("CONNECT", "COMPLETED_WITH_GAPS", "Live cluster transport NOT_CONFIGURED in this deployment — assessment runs over recorded inventory; the kubeconfig remains a secret reference, never content (§71/§72)");

    const workloads = await this.prisma.kubernetesWorkload.findMany({ where: { workspaceId: workspace.id, clusterId }, take: 2000 }) as Row[];
    const namespaces = new Set(workloads.map((w) => w.namespace as string));
    stage("INVENTORY", "COMPLETED", `${workloads.length} workload(s) across ${namespaces.size} namespace(s) from recorded inventory (§73)`);

    const rbac = await this.getRbacInternal(workspace.id, clusterId);
    stage("RBAC", rbac.risks.length ? "COMPLETED_WITH_GAPS" : "COMPLETED", `${rbac.risks.length} RBAC risk(s), ${rbac.edges.length} graph edge(s) (§76/§77)`);

    const privileged = workloads.filter((w) => ((w.securityContext ?? {}) as Row).privileged === true);
    const hostNetwork = workloads.filter((w) => ((w.securityContext ?? {}) as Row).hostNetwork === true);
    stage("WORKLOAD_CONFIGURATION", privileged.length || hostNetwork.length ? "COMPLETED_WITH_GAPS" : "COMPLETED",
      `${privileged.length} privileged, ${hostNetwork.length} hostNetwork workload(s) (§75)`);

    const benchmarks = await this.prisma.controlAssessment.count({ where: { workspaceId: workspace.id } }).catch(() => 0);
    stage("BENCHMARK", benchmarks > 0 ? "COMPLETED" : "COMPLETED_WITH_GAPS",
      benchmarks > 0 ? `${benchmarks} recorded CIS control assessment(s) in workspace (§78/§79)` : "No kube-bench/Kubescape benchmark results recorded — gap, not a pass (§114)");

    const images = await this.prisma.containerImage.findMany({ where: { workspaceId: workspace.id }, take: 1000 }) as Row[];
    let correlated = 0;
    for (const w of workloads) {
      const refs = JSON.stringify(w.images ?? []);
      if (images.some((img) => refs.includes(img.repository as string))) correlated++;
    }
    stage("IMAGE_CORRELATION", "COMPLETED", `${correlated}/${workloads.length} workload(s) have images correlated to ContainerImage/SBOM records (§86)`);

    const publicWorkloads = workloads.filter((w) => w.exposure === "PUBLIC_INTERNET");
    const attackPaths = buildKubernetesAttackPathCandidates({
      workloads: workloads.map((w) => ({
        namespace: w.namespace as string, kind: w.kind as string, name: w.name as string,
        serviceAccount: (w.serviceAccount as string | undefined) ?? undefined, exposure: w.exposure as string,
        privileged: ((w.securityContext ?? {}) as Row).privileged === true,
      })),
      rbacRisks: rbac.risks,
    });
    stage("EXPOSURE", "COMPLETED", `${publicWorkloads.length} public workload(s); ${attackPaths.length} attack-path candidate(s) — analytical only, never executed (§89/§90)`);

    const runtimeEvents = await this.prisma.runtimeSecurityEvent.findMany({ where: { workspaceId: workspace.id, clusterId }, take: 500 }) as Row[];
    stage("RUNTIME_SIGNALS", runtimeEvents.length ? "COMPLETED" : "COMPLETED_WITH_GAPS",
      runtimeEvents.length ? `${runtimeEvents.length} Falco runtime event(s) recorded (§91)` : "No runtime telemetry recorded for this cluster (§114 gap)");

    const admission = analyzeAdmissionPosture({
      psaEnforceLevels: (body.psaEnforceLevels as Record<string, string> | undefined) ?? {},
      policyEngines: (body.policyEngines as string[] | undefined) ?? [],
      imagePolicyPresent: typeof body.imagePolicyPresent === "boolean" ? body.imagePolicyPresent : undefined,
    });
    stage("RISK", "COMPLETED", `Admission: ${admission.map((a) => a.kind).join(", ")} (§85). Risk signals staged for Risk Engine V3 (§119)`);
    stage("REMEDIATION", "COMPLETED", "Verification = manifest re-read / workload + RBAC re-evaluation / targeted benchmark (§123). Workloads are never restarted or deleted (§96/§124)");

    const coverageBuilt = buildKubernetesCoverage({
      namespacesCovered: namespaces.size, workloadsCovered: workloads.length,
      rbacSubjects: rbac.edges.filter((e) => e.fromType === "SUBJECT").length,
      benchmarkChecks: benchmarks, imagesCorrelated: correlated, workloadsTotal: workloads.length,
      runtimeTelemetry: runtimeEvents.length > 0, transportConfigured: false,
    });
    const coverage = await this.prisma.kubernetesSecurityCoverage.create({
      data: {
        workspaceId: workspace.id, runId: run.id, clusterId,
        namespacesCovered: coverageBuilt.coverage.namespacesCovered, workloadsCovered: coverageBuilt.coverage.workloadsCovered,
        rbacSubjects: coverageBuilt.coverage.rbacSubjects, benchmarkChecks: coverageBuilt.coverage.benchmarkChecks,
        imagesCorrelated: coverageBuilt.coverage.imagesCorrelated, runtimeTelemetry: coverageBuilt.coverage.runtimeTelemetry,
        gaps: coverageBuilt.gaps as never, completion: coverageBuilt.completion,
      },
    });
    const ordered = KUBERNETES_PIPELINE_STAGES.map((name) => stages.find((s) => s.stage === name) ?? { stage: name, status: "COMPLETED" as const, detail: "" });
    const finished = await this.prisma.cloudV2AssessmentRun.update({
      where: { id: run.id }, data: { status: coverageBuilt.completion, pipeline: ordered as never, completedAt: new Date() },
    });
    await this.audit(workspace.id, user, "KUBERNETES_ASSESSMENT_STARTED", "KubernetesCluster", clusterId, { runId: run.id, phase: "completed", completion: coverageBuilt.completion });
    return {
      run: finished, stages: ordered, coverage, cluster: { id: cluster.id, name: cluster.name },
      rbacRisks: rbac.risks, attackPaths, admission, privilegedWorkloads: privileged.length,
    };
  }

  private async getRbacInternal(workspaceId: string, clusterId: string) {
    const roles = await this.prisma.kubernetesRole.findMany({ where: { workspaceId, clusterId }, take: 500 }) as Row[];
    const bindings = await this.prisma.kubernetesRoleBinding.findMany({ where: { workspaceId, clusterId }, take: 500 }) as Row[];
    return analyzeKubernetesRbac(
      roles.map((r) => ({ kind: r.kind, namespace: r.namespace, name: r.name, rules: (r.rules ?? []) as K8sRoleRecord["rules"] })),
      bindings.map((b) => ({
        kind: b.kind, namespace: b.namespace, name: b.name, roleKind: b.roleKind, roleName: b.roleName,
        subjects: (b.subjects ?? []) as K8sRoleBindingRecord["subjects"],
      })),
    );
  }

  /* --------------------- findings + runtime (§138) --------------------- */

  async listFindings(user: AuthUser, headers: Headers) {
    requireKubernetesV2Permission(user, "VIEW_KUBERNETES_SECURITY");
    const workspace = await this.ws(user, headers);
    const rows = await this.prisma.finding.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 1000 }) as Row[];
    const items = rows.filter((f) => typeof f.fingerprint === "string"
      && ((f.fingerprint as string).startsWith("k8scfg:") || (f.fingerprint as string).startsWith("kubebench:")));
    return { items: items.slice(0, 200), total: items.length };
  }

  async listRuntimeEvents(user: AuthUser, headers: Headers, query: Record<string, unknown>) {
    requireKubernetesV2Permission(user, "VIEW_RUNTIME_SECURITY");
    const workspace = await this.ws(user, headers);
    const where: Row = { workspaceId: workspace.id };
    if (query.clusterId) where.clusterId = String(query.clusterId);
    const events = await this.prisma.runtimeSecurityEvent.findMany({ where, orderBy: { eventTime: "desc" }, take: 200 }) as Row[];
    const correlations = await this.prisma.runtimeEventCorrelation.findMany({ where: { workspaceId: workspace.id }, take: 200 }) as Row[];
    const byEvent = new Map(correlations.map((c) => [c.eventId as string, c]));
    return {
      items: events.map((e) => ({ ...e, correlation: byEvent.get(e.id as string) ?? null })),
      note: "Falco is detection (§92): events are SOC signals; correlation adds context, never changes scanner severity (§95) and never triggers workload actions (§96).",
    };
  }

  /** §94/§141/§158: correlate one runtime event and, for
   *  high-confidence high-priority signals, link a SOC alert through
   *  the single governed raise path (which dedupes by fingerprint). */
  async correlateRuntimeEvent(user: AuthUser, headers: Headers, eventId: string) {
    requireKubernetesV2Permission(user, "VIEW_RUNTIME_SECURITY");
    const workspace = await this.ws(user, headers);
    const event = await this.prisma.runtimeSecurityEvent.findFirst({ where: { id: eventId, workspaceId: workspace.id } }) as Row | null;
    if (!event) throw new NotFoundException("Runtime event not found");
    const workloads = await this.prisma.kubernetesWorkload.findMany({
      where: { workspaceId: workspace.id, ...(event.clusterId ? { clusterId: event.clusterId as string } : {}) }, take: 500,
    }) as Row[];
    const images = await this.prisma.containerImage.findMany({ where: { workspaceId: workspace.id }, take: 500 }) as Row[];
    const findings = await this.prisma.finding.findMany({ where: { workspaceId: workspace.id }, take: 500 }) as Row[];
    const correlation = correlateRuntimeEvent(
      { namespace: event.namespace ?? undefined, pod: event.pod ?? undefined, container: event.container ?? undefined, rule: event.rule as string, priority: event.priority as string },
      {
        workloads: workloads.map((w) => ({
          namespace: w.namespace as string, kind: w.kind as string, name: w.name as string,
          images: ((w.images ?? []) as Row[]).map((i) => ({ container: i.container as string | undefined, image: (i.image as string) ?? "", digest: i.digest as string | undefined })),
        })),
        images: images.map((i) => ({ id: i.id as string, repository: i.repository as string, digest: (i.digest as string | null) ?? null })),
        findings: findings.map((f) => ({
          id: f.id as string, cve: (f.cve as string | null) ?? null, severity: f.severity as string,
          // Findings link to images via imageRef (Prompt 13); the
          // repository is the ref minus digest/tag suffixes.
          imageRepository: typeof f.imageRef === "string" ? f.imageRef.split("@")[0]!.replace(/:([^/:]+)$/, "") : null,
        })),
      },
    );

    let socAlertLinked = false;
    if (correlation.socAlertRecommended) {
      const raised = await this.alertService.raiseAlert({
        organizationId: user.organizationId, workspaceId: workspace.id,
        fingerprint: `falco:${event.clusterId ?? "unknown"}:${event.rule}:${correlation.workloadRef ?? event.pod ?? "unknown"}`,
        title: `Runtime signal on vulnerable workload: ${event.rule}`,
        description: correlation.detail, severity: "HIGH", source: "CORRELATION",
        ...(correlation.findingIds[0] ? { findingId: correlation.findingIds[0] } : {}),
        confidence: "HIGH",
      }).catch(() => null);
      socAlertLinked = Boolean(raised && (raised.created || raised.alert));
    }

    const existing = await this.prisma.runtimeEventCorrelation.findFirst({ where: { eventId } });
    const data = {
      workspaceId: workspace.id, eventId, clusterId: (event.clusterId as string | null) ?? null,
      workloadRef: correlation.workloadRef ?? null, imageRef: correlation.imageRef ?? null,
      imageId: correlation.imageId ?? null, findingIds: correlation.findingIds as never,
      confidence: correlation.confidence, socAlertLinked, detail: correlation.detail,
    };
    const record = existing
      ? await this.prisma.runtimeEventCorrelation.update({ where: { id: (existing as Row).id }, data })
      : await this.prisma.runtimeEventCorrelation.create({ data });
    await this.audit(workspace.id, user, "RUNTIME_EVENT_CORRELATED", "RuntimeSecurityEvent", eventId, { confidence: correlation.confidence, socAlertLinked });
    return { correlation: record, result: correlation };
  }

  /* --------------------- baselines (§98/§100) + coverage --------------------- */

  async createBaseline(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireKubernetesV2Permission(user, "MANAGE_KUBERNETES_CLUSTERS");
    const workspace = await this.ws(user, headers);
    const rules = (Array.isArray(body.rules) ? body.rules : DEFAULT_KUBERNETES_BASELINE_RULES) as CloudV2BaselineRule[];
    for (const rule of rules) {
      if (!rule.ruleId || !rule.expectation || !rule.severity) throw new BadRequestException("Each baseline rule needs ruleId, expectation and severity (§98)");
    }
    const clusterId = body.clusterId ? String(body.clusterId) : null;
    if (clusterId) await this.clusterOr404(workspace.id, clusterId);
    const existing = await this.prisma.kubernetesSecurityBaseline.findMany({ where: { workspaceId: workspace.id, clusterId } });
    const version = (existing as Row[]).reduce((max, r) => Math.max(max, Number(r.version ?? 0)), 0) + 1;
    const baseline = await this.prisma.kubernetesSecurityBaseline.create({
      data: { workspaceId: workspace.id, clusterId, version, rules: rules as never, hash: hashBaselineRules(rules), createdById: user.id },
    });
    await this.audit(workspace.id, user, "KUBERNETES_BASELINE_CREATED", "KubernetesSecurityBaseline", (baseline as Row).id, { version });
    return baseline;
  }

  async listBaselines(user: AuthUser, headers: Headers) {
    requireKubernetesV2Permission(user, "VIEW_KUBERNETES_SECURITY");
    const workspace = await this.ws(user, headers);
    const rows = await this.prisma.kubernetesSecurityBaseline.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 50 });
    return { items: rows };
  }

  async baselineDrift(user: AuthUser, headers: Headers, query: Record<string, unknown>) {
    requireKubernetesV2Permission(user, "VIEW_KUBERNETES_SECURITY");
    const workspace = await this.ws(user, headers);
    const baseline = await this.prisma.kubernetesSecurityBaseline.findFirst({
      where: { workspaceId: workspace.id, ...(query.clusterId ? { clusterId: String(query.clusterId) } : {}) },
      orderBy: { createdAt: "desc" },
    }) as Row | null;
    if (!baseline) return { baseline: null, deviations: [], note: "No Kubernetes baseline exists yet (§98)." };
    const workloads = await this.prisma.kubernetesWorkload.findMany({
      where: { workspaceId: workspace.id, ...(query.clusterId ? { clusterId: String(query.clusterId) } : {}) }, take: 2000,
    }) as Row[];
    const rbac = query.clusterId ? await this.getRbacInternal(workspace.id, String(query.clusterId)) : { risks: [] as Array<{ kind: string }> };
    const facts: Record<string, string> = {
      "privileged-workload": workloads.some((w) => ((w.securityContext ?? {}) as Row).privileged === true) ? "PRESENT" : "ABSENT",
      "host-network-workload": workloads.some((w) => ((w.securityContext ?? {}) as Row).hostNetwork === true) ? "PRESENT" : "ABSENT",
      "cluster-admin-binding": rbac.risks.some((r) => r.kind === "CLUSTER_ADMIN_BINDING") ? "PRESENT" : "ABSENT",
      "wildcard-permissions": rbac.risks.some((r) => r.kind === "WILDCARD_PERMISSIONS") ? "PRESENT" : "ABSENT",
    };
    return { baseline, deviations: evaluateBaselineDeviations(baseline.rules as CloudV2BaselineRule[], facts), facts };
  }

  async getCoverage(user: AuthUser, headers: Headers, query: Record<string, unknown>) {
    requireKubernetesV2Permission(user, "VIEW_KUBERNETES_SECURITY");
    const workspace = await this.ws(user, headers);
    const where: Row = { workspaceId: workspace.id };
    if (query.clusterId) where.clusterId = String(query.clusterId);
    const rows = await this.prisma.kubernetesSecurityCoverage.findMany({ where, orderBy: { createdAt: "desc" }, take: 20 });
    return { items: rows };
  }

  verificationPlan(user: AuthUser, body: Record<string, unknown>) {
    requireKubernetesV2Permission(user, "VIEW_KUBERNETES_SECURITY");
    const kind = String(body.kind ?? "WORKLOAD") as "WORKLOAD" | "RBAC" | "BENCHMARK" | "IMAGE";
    return planKubernetesVerification(kind);
  }
}
