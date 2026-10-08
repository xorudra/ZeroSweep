import { ForbiddenException, NotFoundException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import { ContainerSecurityService } from "./container-security.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Container Security V2 API tests (Prompt 34 §46–§64/§99–§104/
 * §113/§138/§162) against an in-memory Prisma fake. Scan and SBOM
 * delegate to the Prompt 13 governed paths (stubbed here — those
 * paths carry their own test suites); the V2 subjects are digest
 * identity, image-policy evaluation, the orchestrator, coverage and
 * baselines.
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
      const row = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), lastSeen: new Date(), capturedAt: new Date(), startedAt: new Date(), ...args.data };
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
    containerImage: makeTable([
      { id: "img-1", workspaceId: "ws-1", registryId: "reg-1", reference: "ghcr.io/example/web:latest", registry: "ghcr.io", repository: "example/web", tag: "latest", digest: "sha256:deadbeef", targetId: "target-1" },
      { id: "img-other", workspaceId: "ws-other", registryId: null, reference: "docker.io/x/y:1", registry: "docker.io", repository: "x/y", tag: "1", digest: "sha256:beef", targetId: null },
    ]),
    containerImageSnapshot: makeTable([
      { id: "snap-1", imageId: "img-1", digest: "sha256:deadbeef", config: { user: "root", healthcheckPresent: false }, layers: [], capturedAt: new Date() },
    ]),
    softwareComponent: makeTable([
      { id: "c-1", imageId: "img-1", name: "openssl", version: "3.0.0", purl: "pkg:apk/openssl@3.0.0" },
      { id: "c-2", imageId: "img-1", name: "zlib", version: "1.2", purl: "pkg:apk/zlib@1.2" },
    ]),
    softwareBillOfMaterials: makeTable([{ id: "sbom-1", imageId: "img-1", format: "CYCLONEDX_JSON", checksum: "abc" }]),
    kubernetesWorkload: makeTable([
      { id: "w-1", workspaceId: "ws-1", clusterId: "cluster-1", kind: "Deployment", namespace: "prod", name: "web", images: [{ container: "web", image: "ghcr.io/example/web", digest: "sha256:deadbeef" }], securityContext: {}, exposure: "PUBLIC_INTERNET" },
    ]),
    finding: makeTable([
      { id: "f-1", workspaceId: "ws-1", fingerprint: "imgvuln:aaa", imageRef: "ghcr.io/example/web:latest", severity: "CRITICAL", cve: "CVE-2024-0001", status: "OPEN", createdAt: new Date() },
    ]),
    cloudV2AssessmentRun: makeTable([]),
    containerSecurityCoverage: makeTable([]),
    containerSecurityBaseline: makeTable([]),
  };
  const audit = new AuditService(db as never);
  const cloudNativeStub = {
    startImageScan: async (_user: unknown, id: string) => ({ imageId: id, scanId: "scan-1", delegated: "prompt13-gated-path" }),
    getImageSbom: async (_user: unknown, id: string) => ({ imageId: id, componentCount: 2, format: "CYCLONEDX_JSON" }),
  };
  const service = new ContainerSecurityService(db as never, audit, cloudNativeStub as never);
  return { service, db };
}

const user = (role: Role = "ADMIN"): RequestUser => ({ id: "user-1", organizationId: "org-1", role } as RequestUser);
const headers = { "x-workspace-id": "ws-1" };

describe("ContainerSecurityService", () => {
  it("§49: image identity is the digest, not the mutable tag", async () => {
    const { service } = makeService();
    const out = await service.listImages(user(), headers);
    expect(out.items[0]?.identity).toBe("sha256:deadbeef");
    expect(out.items[0]?.componentCount).toBe(2);
  });

  it("§138: scan delegates to the governed Prompt 13 gated path", async () => {
    const { service } = makeService();
    const out = await service.scanImage(user(), "img-1", {});
    expect((out as Row).scanId).toBe("scan-1");
    expect((out as Row).delegated).toBe("prompt13-gated-path");
  });

  it("§52/§138: SBOM delegates to the Prompt 30 subsystem (no duplicate model)", async () => {
    const { service } = makeService();
    const out = await service.getImageSbom(user(), "img-1");
    expect((out as Row).componentCount).toBe(2);
  });

  it("§104/§62: orchestrator evaluates image policy — latest tag + root user violate", async () => {
    const { service, db } = makeService();
    const out = await service.assessImage(user(), headers, "img-1", {});
    expect(out.policy.compliant).toBe(false);
    expect(out.policy.violations.map((v) => v.rule)).toEqual(expect.arrayContaining(["latest-tag", "root-user"]));
    expect(out.run.status).toBe("COMPLETED_WITH_GAPS");
    expect(db.containerSecurityCoverage.rows).toHaveLength(1);
    expect(out.deployedIn).toHaveLength(1);
  });

  it("§113: coverage records SBOM ratio from observed counts", async () => {
    const { service } = makeService();
    const out = await service.assessImage(user(), headers, "img-1", {});
    expect(out.coverage.sbomCoverage).toBe(1);
    expect(out.coverage.completion).toBe("COMPLETED_WITH_GAPS"); // scanner transport gap is honest
  });

  it("§99/§100: baseline versions increment; drift reflects policy facts", async () => {
    const { service } = makeService();
    const b1 = await service.createBaseline(user(), headers, {});
    expect((b1 as Row).version).toBe(1);
    const drift = await service.baselineDrift(user(), headers);
    expect(drift.deviations.some((d) => d.ruleId === "latest-tag")).toBe(true);
  });

  it("§139: VIEWER cannot scan or assess; §162 foreign image is 404", async () => {
    const { service } = makeService();
    await expect(service.scanImage(user("VIEWER"), "img-1", {})).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.assessImage(user(), headers, "img-other", {})).rejects.toBeInstanceOf(NotFoundException);
  });
});
