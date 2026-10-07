import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { CloudNativeService } from "./cloud-native.service";

/**
 * Prompt 13 §91–§110 API discipline: images/clusters are tenant-
 * isolated; credentials are reference names only (a kubeconfig or
 * password field is refused by the strict schemas and never stored);
 * registry URLs pass the SSRF policy; scan starts are gated on a
 * VERIFIED target; runtime ingestion sanitizes hostile payloads;
 * compliance output never claims certification.
 */

const owner = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const viewer = { id: "u-3", email: "v@example.com", organizationId: "org-1", role: "VIEWER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

interface State {
  targets: Array<Record<string, unknown>>;
  images: Array<Record<string, unknown>>;
  registries: Array<Record<string, unknown>>;
  clusters: Array<Record<string, unknown>>;
  workloads: Array<Record<string, unknown>>;
  assessments: Array<Record<string, unknown>>;
  runtimeEvents: Array<Record<string, unknown>>;
  components: Array<Record<string, unknown>>;
  sboms: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  scopes: Array<Record<string, unknown>>;
  engagements: Array<Record<string, unknown>>;
  audits: Array<Record<string, unknown>>;
}

function freshState(): State {
  return {
    targets: [
      { id: "t-img", workspaceId: "ws-1", name: "registry.example.com/team/webapp:1.4.2", type: "CONTAINER_IMAGE", value: "registry.example.com/team/webapp:1.4.2", verified: false, status: "DRAFT" },
      { id: "t-clu", workspaceId: "ws-1", name: "fixture-cluster", type: "KUBERNETES_CLUSTER", value: "fixture-cluster", verified: true, status: "VERIFIED" },
    ],
    images: [{
      id: "img-1", workspaceId: "ws-1", targetId: "t-img", reference: "registry.example.com/team/webapp:1.4.2",
      registry: "registry.example.com", repository: "team/webapp", tag: "1.4.2", digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      platform: null, source: "MANUAL", firstSeen: new Date(0), lastSeen: new Date(0),
    }],
    registries: [],
    clusters: [{
      id: "clu-1", workspaceId: "ws-1", targetId: "t-clu", name: "fixture-cluster",
      apiServerReference: "fixture-apiserver", credentialReference: "prod-kubeconfig", provider: null, version: "1.30",
      namespaces: [], createdAt: new Date(0), lastInventoryAt: null, lastAssessmentAt: null,
    }],
    workloads: [{
      id: "w-1", clusterId: "clu-1", workspaceId: "ws-1", kind: "Deployment", namespace: "prod", name: "webapp",
      replicas: 2, serviceAccount: "webapp", images: [], securityContext: {}, exposure: "INTERNAL", lastSeen: new Date(0),
    }],
    assessments: [], runtimeEvents: [], components: [], sboms: [], findings: [], scopes: [], engagements: [], audits: [],
  };
}

const WORKSPACES = [
  { id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date(0) },
  { id: "ws-2", organizationId: "org-2", deletedAt: null, createdAt: new Date(0) },
];

let seq = 100;
function fakePrisma(state: State) {
  const match = (row: Record<string, unknown>, where: Record<string, unknown> = {}) =>
    Object.entries(where).every(([k, v]) => v === undefined || row[k] === v);
  const model = (rows: Array<Record<string, unknown>>, prefix: string) => ({
    findMany: async (args: { where?: Record<string, unknown> } = {}) => rows.filter((r) => match(r, args.where)),
    findFirst: async (args: { where?: Record<string, unknown> } = {}) => rows.find((r) => match(r, args.where)) ?? null,
    findUnique: async (args: { where: { id: string } }) => rows.find((r) => r.id === args.where.id) ?? null,
    count: async (args: { where?: Record<string, unknown> } = {}) => rows.filter((r) => match(r, args.where)).length,
    create: async (args: { data: Record<string, unknown> }) => {
      const row = { id: `${prefix}-${++seq}`, createdAt: new Date(0), ...args.data };
      rows.push(row);
      return row;
    },
    update: async (args: { where: { id: string }; data: Record<string, unknown> }) => {
      const row = rows.find((r) => r.id === args.where.id);
      if (row) Object.assign(row, args.data);
      return row;
    },
  });
  return {
    workspace: {
      findFirst: async (args: { where: { organizationId: string } }) =>
        WORKSPACES.find((w) => w.organizationId === args.where.organizationId) ?? null,
    },
    target: model(state.targets, "t"),
    containerImage: model(state.images, "img"),
    containerImageSnapshot: model([], "snap"),
    containerRegistry: model(state.registries, "reg"),
    kubernetesCluster: model(state.clusters, "clu"),
    kubernetesWorkload: model(state.workloads, "w"),
    controlAssessment: model(state.assessments, "ca"),
    runtimeSecurityEvent: model(state.runtimeEvents, "evt"),
    softwareComponent: model(state.components, "cmp"),
    softwareBillOfMaterials: model(state.sboms, "sbom"),
    finding: {
      ...model(state.findings, "f"),
      groupBy: async () => [],
    },
    scope: model(state.scopes, "scp"),
    assessment: model(state.engagements, "asm"),
  };
}

function makeService(state: State) {
  const prisma = fakePrisma(state);
  const audit = { record: async (e: Record<string, unknown>) => { state.audits.push(e); } };
  const orchestration = { startScan: async () => ({ scanId: "scan-1", status: "QUEUED" }) };
  return new CloudNativeService(prisma as never, audit as never, orchestration as never);
}

describe("Prompt 13 API — container images", () => {
  it("registers an image as target + inventory row and audits it (§91/§111)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const out = await svc.registerImage(owner, { image: "ghcr.io/example/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" });
    expect(out.verified).toBe(false);
    expect(state.images.some((i) => i.digest === "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")).toBe(true);
    expect(state.audits.some((a) => a.action === "CONTAINER_IMAGE_REGISTERED")).toBe(true);
  });

  it("refuses malformed references and viewer registrations", async () => {
    const svc = makeService(freshState());
    await expect(svc.registerImage(owner, { image: "not a reference!!" })).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.registerImage(viewer, { image: "ghcr.io/example/api:1" })).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("is tenant-isolated: foreign org cannot see the image (§110)", async () => {
    const svc = makeService(freshState());
    await expect(svc.getImage(foreign, "img-1")).rejects.toBeInstanceOf(NotFoundException);
    const list = await svc.listImages(foreign);
    expect(list.items).toHaveLength(0);
  });

  it("scan start is gated on a VERIFIED image target (§4)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.startImageScan(owner, "img-1", {})).rejects.toBeInstanceOf(BadRequestException);
    (state.targets[0] as Record<string, unknown>).verified = true;
    const out = await svc.startImageScan(owner, "img-1", { profile: "CONTAINER_BASELINE" });
    expect(out.scanId).toBe("scan-1");
    expect(state.audits.some((a) => a.action === "CONTAINER_SCAN_STARTED")).toBe(true);
  });

  it("generates the image SBOM from persisted components only (§12)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.getImageSbom(owner, "img-1")).rejects.toBeInstanceOf(NotFoundException);
    state.components.push({
      id: "c-1", imageId: "img-1", name: "openssl", version: "1.1.1n", ecosystem: "deb",
      purl: "pkg:deb/debian/openssl@1.1.1n", sourceManifest: "syft:image", scope: "RUNTIME",
      dependencyScope: "RUNTIME", licenses: [], supplier: null,
    });
    const sbom = await svc.getImageSbom(owner, "img-1");
    expect(sbom.componentCount).toBe(1);
    expect(state.sboms).toHaveLength(1);
  });
});

describe("Prompt 13 API — registries & clusters", () => {
  it("registry URLs pass the SSRF policy; credentials are reference names (§6/§107)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.createRegistry(owner, { name: "internal", url: "https://10.0.0.5:5000" })).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.createRegistry(owner, { name: "creds-in-url", url: "https://user:pass@registry.example.com" })).rejects.toBeInstanceOf(BadRequestException);
    const ok = await svc.createRegistry(owner, { name: "prod", url: "https://registry.example.com", credentialReference: "prod-registry-creds" });
    expect(ok.id).toBeTruthy();
    const list = await svc.listRegistries(owner);
    expect(JSON.stringify(list)).toContain("prod-registry-creds");
    expect(JSON.stringify(list)).not.toContain("password");
  });

  it("cluster registration stores references only — never a credential value (§33)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const out = await svc.createCluster(owner, {
      name: "prod-eu", apiServerReference: "prod-eu-apiserver", credentialReference: "prod-eu-kubeconfig",
    });
    expect(out.id).toBeTruthy();
    const stored = state.clusters.find((c) => c.id === out.id)!;
    expect(Object.keys(stored)).not.toContain("kubeconfig");
    expect(Object.keys(stored)).not.toContain("token");
    expect(stored.credentialReference).toBe("prod-eu-kubeconfig");
    await expect(svc.createCluster(viewer, { name: "x", apiServerReference: "ref" })).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("cluster scan runs on the verified fixture cluster (§91)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const out = await svc.startClusterScan(owner, "clu-1", {});
    expect(out.scanId).toBe("scan-1");
    expect(state.audits.some((a) => a.action === "KUBERNETES_SCAN_STARTED")).toBe(true);
  });
});

describe("Prompt 13 API — compliance & runtime events", () => {
  it("compliance output carries the no-certification disclaimer (§88)", async () => {
    const state = freshState();
    state.assessments.push({ id: "ca-1", workspaceId: "ws-1", frameworkKey: "CIS_KUBERNETES", controlId: "5.2.6", subjectRef: "Deployment/prod/webapp", status: "FAIL", evidence: "runs as root", assessedAt: new Date(0), scanId: "scan-1" });
    const svc = makeService(state);
    const out = await svc.listComplianceAssessments(owner, {});
    expect(out.disclaimer).toContain("not a compliance certification");
    expect(out.byStatus.FAIL).toBe(1);
  });

  it("runtime ingestion sanitizes hostile payloads before storage (§60)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const out = await svc.ingestRuntimeEvent(owner, {
      rule: "Terminal shell in container",
      priority: "WARNING",
      time: "2026-10-07T00:00:00.000Z",
      namespace: "prod", pod: "webapp-abc", container: "webapp", node: "node-1",
      // Hostile field content: terminal escape sequences + a forged
      // log line — the \u00a760 log-injection / terminal-escape vectors.
      outputFields: { proc_cmdline: "sh -c id\u001b[31m\nFAKE LOG LINE severity=CRITICAL" },
    });
    expect(out.ingested).toBe(true);
    const stored = JSON.stringify(state.runtimeEvents[0]);
    expect(stored).not.toContain("\\u001b");
    expect(stored).not.toContain("\\nFAKE");
    expect(state.audits.some((a) => a.action === "RUNTIME_EVENT_INGESTED")).toBe(true);
    await expect(svc.ingestRuntimeEvent(viewer, { rule: "X", priority: "NOTICE", time: "2026-10-07T00:00:00.000Z" })).rejects.toBeInstanceOf(ForbiddenException);
  });
});
