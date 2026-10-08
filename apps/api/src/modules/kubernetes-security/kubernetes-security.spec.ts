import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import { KubernetesSecurityService } from "./kubernetes-security.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Kubernetes Security V2 API tests (Prompt 34 §70–§96/§98–§105/
 * §114/§138–§141/§152–§158/§162) against an in-memory Prisma fake.
 * Subjects: RBAC inventory hygiene (no tokens/secrets, ever), RBAC
 * analysis, the orchestrator, attack-path candidates, Falco → SOC
 * correlation, baselines and cross-tenant isolation.
 */

type Row = Record<string, any>;
let seq = 0;

function makeTable(rows: Row[] = []) {
  const matches = (row: Row, where: Row = {}) =>
    Object.entries(where).every(([k, v]) => {
      if (v === null || typeof v !== "object" || v instanceof Date) return row[k] === v || (v === null && (row[k] === null || row[k] === undefined));
      return true;
    });
  return {
    rows,
    async findFirst(args: { where?: Row } = {}) { return rows.find((r) => matches(r, args.where)) ?? null; },
    async findMany(args: { where?: Row; take?: number } = {}) {
      const found = rows.filter((r) => matches(r, args.where));
      return args.take ? found.slice(0, args.take) : found;
    },
    async count(args: { where?: Row } = {}) { return rows.filter((r) => matches(r, args.where)).length; },
    async create(args: { data: Row }) {
      const row = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), startedAt: new Date(), eventTime: new Date(), firstSeen: new Date(), lastSeen: new Date(), ...args.data };
      rows.push(row);
      return row;
    },
    async update(args: { where: Row; data: Row }) {
      const row = rows.find((r) => matches(r, args.where));
      if (!row) throw new Error("not found");
      Object.assign(row, args.data);
      return row;
    },
  };
}

function makeService() {
  const db = {
    workspace: makeTable([{ id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date() }]),
    auditLog: makeTable([]),
    kubernetesCluster: makeTable([
      { id: "cluster-1", workspaceId: "ws-1", name: "prod-eks", provider: "EKS", credentialReference: "vault:k8s/prod-ro", apiServerReference: "eks-prod-ref", environment: "PRODUCTION", criticality: "HIGH" },
      { id: "cluster-other", workspaceId: "ws-other", name: "foreign", provider: "GKE", credentialReference: "vault:x", apiServerReference: "ref", environment: "PRODUCTION", criticality: "LOW" },
    ]),
    kubernetesWorkload: makeTable([
      { id: "w-1", workspaceId: "ws-1", clusterId: "cluster-1", kind: "Deployment", namespace: "prod", name: "web", serviceAccount: "web-sa", images: [{ container: "web", image: "ghcr.io/example/web", digest: "sha256:deadbeef" }], securityContext: { privileged: true }, exposure: "PUBLIC_INTERNET" },
      { id: "w-2", workspaceId: "ws-1", clusterId: "cluster-1", kind: "Deployment", namespace: "prod", name: "api", serviceAccount: "api-sa", images: [{ container: "api", image: "ghcr.io/example/api", digest: "sha256:cafe" }], securityContext: {}, exposure: "CLUSTER_INTERNAL" },
    ]),
    kubernetesRole: makeTable([
      { id: "role-1", workspaceId: "ws-1", clusterId: "cluster-1", kind: "ClusterRole", namespace: null, name: "wildcard-admin", rules: [{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }], labels: {} },
    ]),
    kubernetesRoleBinding: makeTable([
      { id: "bind-1", workspaceId: "ws-1", clusterId: "cluster-1", kind: "ClusterRoleBinding", namespace: null, name: "wildcard-binding", roleKind: "ClusterRole", roleName: "wildcard-admin", subjects: [{ kind: "ServiceAccount", name: "web-sa", namespace: "prod" }] },
    ]),
    runtimeSecurityEvent: makeTable([
      { id: "evt-1", workspaceId: "ws-1", clusterId: "cluster-1", namespace: "prod", pod: "web-7d9c4b6f8-abc12", container: "web", rule: "Terminal shell in container", priority: "CRITICAL", eventTime: new Date(), metadata: {}, source: "FALCO" },
    ]),
    runtimeEventCorrelation: makeTable([]),
    containerImage: makeTable([
      { id: "img-1", workspaceId: "ws-1", repository: "example/web", reference: "ghcr.io/example/web:latest", digest: "sha256:deadbeef", registry: "ghcr.io", tag: "latest" },
    ]),
    finding: makeTable([
      { id: "find-1", workspaceId: "ws-1", fingerprint: "imgvuln:aaa", imageRef: "ghcr.io/example/web:latest", severity: "CRITICAL", cve: "CVE-2024-0001", status: "OPEN", createdAt: new Date() },
      { id: "find-2", workspaceId: "ws-1", fingerprint: "k8scfg:bbb", severity: "HIGH", status: "OPEN", createdAt: new Date() },
    ]),
    controlAssessment: makeTable([]),
    cloudV2AssessmentRun: makeTable([]),
    kubernetesSecurityCoverage: makeTable([]),
    kubernetesSecurityBaseline: makeTable([]),
  };
  const audit = new AuditService(db as never);
  const raised: Row[] = [];
  const alertStub = {
    raiseAlert: async (input: Row) => { raised.push(input); return { alert: { id: "alert-1" }, created: true, suppressed: false }; },
  };
  const service = new KubernetesSecurityService(db as never, audit, alertStub as never);
  return { service, db, raised };
}

const user = (role: Role = "ADMIN"): RequestUser => ({ id: "user-1", organizationId: "org-1", role } as RequestUser);
const headers = { "x-workspace-id": "ws-1" };

describe("KubernetesSecurityService", () => {
  it("§76/§152: RBAC analysis flags wildcard + cluster-admin binding; privileges never used", async () => {
    const { service } = makeService();
    const out = await service.getRbac(user(), headers, "cluster-1");
    expect(out.risks.some((r) => r.kind === "WILDCARD_PERMISSIONS")).toBe(true);
    expect(out.risks.some((r) => r.kind === "CLUSTER_ADMIN_BINDING" && r.severity === "CRITICAL")).toBe(true);
    expect(out.edges.some((e) => e.relationship === "BOUND_TO")).toBe(true);
  });

  it("§83/§84: RBAC import refuses token/secret-shaped subject fields outright", async () => {
    const { service } = makeService();
    await expect(service.importRbac(user(), headers, "cluster-1", {
      bindings: [{ kind: "RoleBinding", namespace: "prod", name: "b", roleKind: "Role", roleName: "r", subjects: [{ kind: "ServiceAccount", name: "x", token: "eyJhbGciOi" }] }],
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("§76: RBAC import stores roles/bindings as data", async () => {
    const { service, db } = makeService();
    const out = await service.importRbac(user(), headers, "cluster-1", {
      roles: [{ kind: "Role", namespace: "prod", name: "reader", rules: [{ resources: ["pods"], verbs: ["get", "list"] }] }],
      bindings: [],
    });
    expect(out.roles).toBe(1);
    expect(db.kubernetesRole.rows).toHaveLength(2);
  });

  it("§105/§89: orchestrator runs the pipeline; attack-path candidate is analytical", async () => {
    const { service, db } = makeService();
    const out = await service.assessCluster(user(), headers, "cluster-1", {});
    expect(out.run.status).toBe("COMPLETED_WITH_GAPS");
    expect(out.stages.map((s) => s.stage)).toEqual(expect.arrayContaining(["RBAC", "WORKLOAD_CONFIGURATION", "RUNTIME_SIGNALS"]));
    expect(out.privilegedWorkloads).toBe(1);
    expect(out.attackPaths.length).toBe(1);
    expect(out.attackPaths[0]?.executed).toBe(false);
    expect(db.kubernetesSecurityCoverage.rows).toHaveLength(1);
  });

  it("§158/§141: Falco event correlates to workload + image + CVE and links a SOC alert once", async () => {
    const { service, db, raised } = makeService();
    const out = await service.correlateRuntimeEvent(user(), headers, "evt-1");
    expect(out.result.workloadRef).toBe("prod/Deployment/web");
    expect(out.result.imageId).toBe("img-1");
    expect(out.result.findingIds).toEqual(["find-1"]);
    expect(out.result.confidence).toBe("HIGH");
    expect(out.result.socAlertRecommended).toBe(true);
    expect(raised).toHaveLength(1);
    expect(raised[0]?.source).toBe("CORRELATION");
    expect(db.runtimeEventCorrelation.rows).toHaveLength(1);
  });

  it("§138: kubernetes findings surface returns k8scfg/kubebench findings only", async () => {
    const { service } = makeService();
    const out = await service.listFindings(user(), headers);
    expect(out.total).toBe(1);
    expect(out.items[0]?.id).toBe("find-2");
  });

  it("§98/§100: baseline create + drift from current workload/RBAC facts", async () => {
    const { service } = makeService();
    const baseline = await service.createBaseline(user(), headers, { clusterId: "cluster-1" });
    expect((baseline as Row).version).toBe(1);
    const drift = await service.baselineDrift(user(), headers, { clusterId: "cluster-1" });
    expect(drift.deviations.some((d) => d.ruleId === "privileged-workload")).toBe(true);
    expect(drift.deviations.some((d) => d.ruleId === "cluster-admin-binding")).toBe(true);
  });

  it("§139/§162: ANALYST cannot view RBAC; foreign cluster is 404", async () => {
    const { service } = makeService();
    await expect(service.getRbac(user("ANALYST"), headers, "cluster-1")).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.assessCluster(user(), headers, "cluster-other", {})).rejects.toBeInstanceOf(NotFoundException);
  });
});
