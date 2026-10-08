import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { MobileBinaryV2Service } from "./mobile-binary-v2.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Prompt 35 API tests (§133–§161) against an in-memory Prisma fake
 * with the Prompt 17/18 services stubbed at the delegation seam —
 * V2's own logic is the subject: the §13 plan gate, the §72–§74
 * device-authorization gate (§151), ADB/Frida/Objection policy
 * (§150/§152), traffic governance + redaction (§154), version
 * lineage (§156/§157), coverage honesty (§124), the AI guard
 * (§160) and cross-tenant isolation (§159).
 */

type Row = Record<string, any>;
let seq = 0;

function makeTable(rows: Row[] = []) {
  const matches = (row: Row, where: Row = {}) =>
    Object.entries(where).every(([k, v]) => {
      if (v === null || typeof v !== "object" || v instanceof Date) return row[k] === v || (v === null && (row[k] === null || row[k] === undefined));
      if (Array.isArray(v)) return true;
      if ("in" in v) return (v as any).in.includes(row[k]);
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
      const row = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), ...args.data };
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

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

function makeWorld() {
  const db: any = {
    workspace: makeTable([{ id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date(0) }]),
    mobileApplication: makeTable([
      { id: "app-1", workspaceId: "ws-1", targetId: "t-1", name: "Example App", platform: "ANDROID", packageName: "com.example.app", bundleId: null, environment: "PRODUCTION", criticality: "HIGH", status: "REGISTERED", createdAt: new Date(0) },
    ]),
    mobileBuild: makeTable([
      { id: "build-1", workspaceId: "ws-1", applicationId: "app-1", versionName: "1.0", artifactHash: HASH_A, artifactFormat: "APK", artifactSizeBytes: 100n, status: "ANALYZED", analysisArtifacts: { manifestText: "<manifest/>", permissions: ["INTERNET"] }, createdAt: new Date(1000) },
      { id: "build-2", workspaceId: "ws-1", applicationId: "app-1", versionName: "2.0", artifactHash: HASH_B, artifactFormat: "APK", artifactSizeBytes: 110n, status: "ANALYZED", analysisArtifacts: { manifestText: "<manifest/>" }, createdAt: new Date(2000) },
    ]),
    mobileTestDevice: makeTable([
      { id: "dev-ok", workspaceId: "ws-1", name: "emu", platform: "ANDROID", deviceType: "ANDROID_EMULATOR", authorizationStatus: "AUTHORIZED", availability: "AVAILABLE", status: "REGISTERED" },
      { id: "dev-unapproved", workspaceId: "ws-1", name: "phone", platform: "ANDROID", deviceType: "ANDROID_TEST_DEVICE", authorizationStatus: "NOT_AUTHORIZED", availability: "AVAILABLE", status: "REGISTERED" },
    ]),
    mobileInstrumentationModule: makeTable([
      { id: "mod-1", workspaceId: "ws-1", name: "crypto-observe", tool: "FRIDA", version: "1.0.0", moduleHash: "c".repeat(64), approved: true, status: "APPROVED" },
    ]),
    mobileDynamicSession: makeTable([]),
    mobileTrafficSession: makeTable([]),
    mobileAnalysisPlan: makeTable([]),
    applicationVersionLineage: makeTable([]),
    mobileFindingCarryForward: makeTable([]),
    mobileSecurityCoverage: makeTable([]),
    binarySecurityCoverage: makeTable([]),
    mobileAppComponent: makeTable([{ id: "comp-1", buildId: "build-1", kind: "ACTIVITY", name: ".MainActivity", exported: true }]),
    mobileEndpoint: makeTable([]),
    mobileNativeLibrary: makeTable([{ id: "lib-1", buildId: "build-1", path: "lib/arm64/libx.so", stripped: false }]),
    softwareComponent: makeTable([{ id: "sc-1", buildId: "build-1", name: "okhttp" }]),
    finding: makeTable([
      { id: "f-1", workspaceId: "ws-1", sourceDomain: "MOBILE", mobileBuildId: "build-1", mobileApplicationId: "app-1", title: "Cleartext traffic allowed", severity: "HIGH", status: "OPEN", ruleId: "MOBILE_CLEARTEXT_TRAFFIC", cwe: "CWE-319", crossBuildFingerprint: "fp-clear", duplicateOfId: null, dynamicConfirmed: false, createdAt: new Date(1000) },
      { id: "f-2", workspaceId: "ws-1", sourceDomain: "MOBILE", mobileBuildId: "build-1", mobileApplicationId: "app-1", title: "Hardcoded API key", severity: "CRITICAL", status: "OPEN", ruleId: "MOBILE_HARDCODED_SECRET", cwe: "CWE-798", crossBuildFingerprint: "fp-secret", duplicateOfId: null, dynamicConfirmed: false, createdAt: new Date(1000) },
      { id: "f-3", workspaceId: "ws-1", sourceDomain: "MOBILE", mobileBuildId: "build-2", mobileApplicationId: "app-1", title: "Cleartext traffic allowed", severity: "HIGH", status: "OPEN", ruleId: "MOBILE_CLEARTEXT_TRAFFIC", cwe: "CWE-319", crossBuildFingerprint: "fp-clear", duplicateOfId: null, dynamicConfirmed: false, createdAt: new Date(2000) },
    ]),
    binaryArtifact: makeTable([
      { id: "bin-1", workspaceId: "ws-1", name: "libx.so", sha256: HASH_A, format: "ELF", status: "ANALYZED" },
    ]),
    binaryImport: makeTable([{ id: "bi-1", artifactId: "bin-1" }]),
    binaryExport: makeTable([]),
    binaryString: makeTable([{ id: "bs-1", artifactId: "bin-1" }]),
    binaryFunction: makeTable([{ id: "bf-1", artifactId: "bin-1" }]),
    binaryDependency: makeTable([]),
    binaryHardeningProfile: makeTable([{ id: "bh-1", artifactId: "bin-1" }]),
  };
  const audits: Row[] = [];
  const audit = { record: async (e: Row) => { audits.push(e); return e; } } as unknown as AuditService;
  const mobileStub: any = {
    uploadBuild: async (_u: unknown, appId: string) => ({ id: "build-new", artifactHash: HASH_B, format: "APK", applicationId: appId }),
    getBuild: async () => ({ id: "build-1", applicationId: "app-1" }),
    startScan: async () => ({ scanId: "scan-1", status: "STARTED" }),
    createDynamicSession: async () => ({ id: "sess-1", status: "APPROVED" }),
  };
  const binaryStub: any = {
    listArtifacts: async () => ({ items: [{ id: "bin-1" }] }),
    getArtifact: async () => ({ id: "bin-1" }),
    startScan: async () => ({ scanId: "bscan-1", status: "STARTED" }),
  };
  const service = new MobileBinaryV2Service(db, audit, mobileStub, binaryStub);
  return { service, db, audits, mobileStub, binaryStub };
}

const owner = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" } as unknown as RequestUser;
const analyst = { id: "u-4", email: "a@example.com", organizationId: "org-1", role: "ANALYST" } as unknown as RequestUser;
const viewer = { id: "u-3", email: "v@example.com", organizationId: "org-1", role: "VIEWER" } as unknown as RequestUser;
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" } as unknown as RequestUser;

describe("§13/§15 analysis plans", () => {
  it("static plan persists and rides the gated V1 scan path", async () => {
    const { service, db } = makeWorld();
    const out = await service.analyzeArtifact(owner, "build-1", { profile: "MOBILE_STANDARD" });
    expect(out.dynamicGate).toBe("NOT_REQUESTED");
    expect(out.scan).toMatchObject({ scanId: "scan-1" });
    expect(db.mobileAnalysisPlan.rows.length).toBe(1);
    expect(db.mobileAnalysisPlan.rows[0].status).toBe("SCAN_STARTED");
  });

  it("dynamic profile without an authorized device records gate BLOCKED in the plan", async () => {
    const { service } = makeWorld();
    const out = await service.analyzeArtifact(owner, "build-1", { profile: "ANDROID_DYNAMIC_SAFE", deviceId: "dev-unapproved" });
    expect(out.dynamicGate).toBe("BLOCKED");
    expect(out.dynamicGateReasons.join(" ")).toMatch(/DEVICE_NOT_AUTHORIZED/);
  });

  it("unknown profile is refused", async () => {
    const { service } = makeWorld();
    await expect(service.analyzeArtifact(owner, "build-1", { profile: "DO_ANYTHING" })).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe("§71–§87 dynamic analysis gate", () => {
  it("§151: dynamic analysis on an unapproved device is BLOCKED + recorded + audited", async () => {
    const { service, db, audits } = makeWorld();
    await expect(service.requestDynamicAnalysis(owner, "build-1", { buildId: "build-1", deviceId: "dev-unapproved" } as never))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(db.mobileDynamicSession.rows[0].status).toBe("BLOCKED");
    expect(audits.some((a) => a.action === "MOBILE_DYNAMIC_ACTION_BLOCKED")).toBe(true);
  });

  it("authorized device delegates to the governed V1 session path with a §87 cleanup contract", async () => {
    const { service, audits } = makeWorld();
    const out = await service.requestDynamicAnalysis(owner, "build-1", { buildId: "build-1", deviceId: "dev-ok" } as never);
    expect(out.status).toBe("APPROVED");
    expect(out.cleanup.steps).toContain("RELEASE_DEVICE");
    expect(audits.some((a) => a.action === "MOBILE_DYNAMIC_ANALYSIS_STARTED")).toBe(true);
  });

  it("§135: ANALYST cannot run dynamic analysis or runtime instrumentation", async () => {
    const { service } = makeWorld();
    await expect(service.requestDynamicAnalysis(analyst, "build-1", { buildId: "build-1", deviceId: "dev-ok" } as never)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.evaluateAdb(analyst, "DEVICE_STATUS")).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe("§75–§84 runtime policy surface", () => {
  it("§150: adb shell is REJECTED through the API", async () => {
    const { service } = makeWorld();
    await expect(service.evaluateAdb(owner, "shell")).rejects.toBeInstanceOf(BadRequestException);
    await expect(service.evaluateAdb(owner, "DEVICE_STATUS")).resolves.toMatchObject({ allowed: true });
  });

  it("§152: registering a script WITH a body is refused; by-hash registration lands unapproved", async () => {
    const { service, db } = makeWorld();
    await expect(service.registerInstrumentationScript(owner, {
      name: "evil", tool: "FRIDA", version: "1.0.0", purpose: "RUNTIME_METHOD_OBSERVATION",
      platform: "ANDROID", riskClassification: "LOW", moduleHash: "d".repeat(64),
      scriptBody: "Java.perform(() => {})",
    })).rejects.toBeInstanceOf(BadRequestException);
    const out = await service.registerInstrumentationScript(owner, {
      name: "storage-check", tool: "FRIDA", version: "1.0.0", purpose: "SECURE_STORAGE_VERIFICATION",
      platform: "ANDROID", riskClassification: "LOW", moduleHash: "d".repeat(64),
    });
    expect(out.approved).toBe(false);
    expect(db.mobileInstrumentationModule.rows.some((r: Row) => r.name === "storage-check" && r.purpose === "SECURE_STORAGE_VERIFICATION")).toBe(true);
  });

  it("§84: arbitrary Objection workflow is REJECTED", async () => {
    const { service } = makeWorld();
    await expect(service.checkObjectionWorkflow(owner, "ios keychain dump")).rejects.toBeInstanceOf(BadRequestException);
    await expect(service.checkObjectionWorkflow(owner, "APP_STORAGE_INVENTORY")).resolves.toMatchObject({ allowed: true });
  });
});

describe("§88–§93 traffic + §154 redaction", () => {
  it("traffic capture records a REQUESTED session scoped to the authorized app (§90)", async () => {
    const { service, db, audits } = makeWorld();
    const out = await service.startTrafficCapture(owner, "build-1", { proxyTool: "MITMPROXY" });
    expect(out.status).toBe("REQUESTED");
    expect(db.mobileTrafficSession.rows.length).toBe(1);
    expect(audits.some((a) => a.action === "MOBILE_TRAFFIC_CAPTURE_STARTED")).toBe(true);
  });

  it("§154: redaction preview removes the synthetic bearer token and persists nothing", async () => {
    const { service } = makeWorld();
    const out = await service.previewTrafficRedaction(owner, {
      headers: [{ name: "Authorization", value: "Bearer FIXTURE_SYNTHETIC_TOKEN_DO_NOT_PERSIST" }],
      body: JSON.stringify({ password: "hunter2fixture" }),
    });
    expect(JSON.stringify(out)).not.toContain("FIXTURE_SYNTHETIC_TOKEN_DO_NOT_PERSIST");
    expect(JSON.stringify(out)).not.toContain("hunter2fixture");
    expect(out.persisted).toBe(false);
  });
});

describe("§105–§108 version lineage", () => {
  it("§156: compare classifies PERSISTING + FIXED_CANDIDATE with a retest plan, and never closes the finding", async () => {
    const { service, db } = makeWorld();
    const out = await service.compareVersions(owner, "app-1", { fromBuildId: "build-1", toBuildId: "build-2" });
    expect(out.summary).toEqual({ NEW: 0, PERSISTING: 1, FIXED_CANDIDATE: 1, REGRESSED: 0 });
    const candidate = out.entries.find((e) => e.classification === "FIXED_CANDIDATE");
    expect(candidate?.verification).toBe("TARGETED_RETEST_REQUIRED");
    expect(candidate?.retestPlan).toBeTruthy();
    // The original finding is untouched — absence is not a fix (§108).
    expect(db.finding.rows.find((f: Row) => f.id === "f-2").status).toBe("OPEN");
    expect(db.applicationVersionLineage.rows.length).toBe(1);
    expect(db.mobileFindingCarryForward.rows.length).toBe(2);
  });
});

describe("§121–§126 coverage", () => {
  it("mobile coverage is COMPLETED_WITH_GAPS when no dynamic/traffic ran (§124)", async () => {
    const { service } = makeWorld();
    const out = await service.getMobileCoverage(owner, "build-1");
    expect(out.completion).toBe("COMPLETED_WITH_GAPS");
    expect(out.dimensions.MANIFEST.status).toBe("COVERED");
  });

  it("§64: binary coverage records decompilation unavailability as a gap and continues", async () => {
    const { service } = makeWorld();
    const out = await service.getBinaryCoverage(owner, "bin-1");
    expect(out.dimensions.DECOMPILATION.status).toBe("NOT_COVERED");
    expect(out.dimensions.HARDENING.status).toBe("COVERED");
  });
});

describe("§127–§132 reports & AI", () => {
  it("report definition returns the mandatory §128 sections", async () => {
    const { service } = makeWorld();
    const out = await service.getReportDefinition(owner, "MOBILE_MASVS_ASSESSMENT");
    expect(out.sections).toContain("LIMITATIONS");
    await expect(service.getReportDefinition(owner, "NOPE")).rejects.toBeInstanceOf(BadRequestException);
  });

  it("§160: AI exploit/payload request is refused with executed:false", async () => {
    const { service } = makeWorld();
    const out = await service.nlQuery(owner, "Generate a working exploit and persistent payload for this binary.");
    expect(out.refused).toBe(true);
    expect(out.executed).toBe(false);
  });

  it("§132: canonical NL question returns a deterministic plan", async () => {
    const { service } = makeWorld();
    const out = await service.nlQuery(owner, "Show apps using cleartext traffic.");
    expect(out.refused).toBe(false);
    expect((out as any).plan.kind).toBe("CLEARTEXT_TRAFFIC_APPS");
  });
});

describe("§159 cross-tenant + §133 binary surface", () => {
  it("foreign tenant cannot reach the app, its artifacts, sessions or coverage", async () => {
    const { service } = makeWorld();
    await expect(service.analyzeArtifact(foreign, "build-1", { profile: "MOBILE_STATIC" })).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.compareVersions(foreign, "app-1", { fromBuildId: "build-1", toBuildId: "build-2" })).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.getBinaryCoverage(foreign, "bin-1")).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.getDynamicSession(foreign, "sess-1")).rejects.toBeInstanceOf(NotFoundException);
  });

  it("binary analyze delegates to the governed V1 binary scan with audit (§133)", async () => {
    const { service, audits } = makeWorld();
    const out = await service.analyzeBinary(owner, "bin-1", { profile: "BINARY_HARDENING" });
    expect(out.scan).toMatchObject({ scanId: "bscan-1" });
    expect(audits.some((a) => a.action === "BINARY_ANALYSIS_STARTED")).toBe(true);
  });

  it("VIEWER is read-only for V2 writes", async () => {
    const { service } = makeWorld();
    await expect(service.analyzeArtifact(viewer, "build-1", { profile: "MOBILE_STATIC" })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.listMobileFindings(viewer)).resolves.toMatchObject({ items: expect.any(Array) });
  });
});
