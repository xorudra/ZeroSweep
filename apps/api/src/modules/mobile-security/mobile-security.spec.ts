import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { FIXTURE_BUILD_HASH, FIXTURE_SECRET_VALUE } from "@zerosweep/security-sdk";
import { MobileSecurityService } from "./mobile-security.service";

/**
 * Prompt 17 §100–§116 API discipline: applications + builds are
 * tenant-isolated; build intake runs the hostile-content validator
 * (archive attacks refused, hash identity enforced); extracted
 * endpoints stay DISCOVERED_REFERENCE; the planted FAKE secret value
 * is redacted before persistence and exists in NO record; scans are
 * gated on a VERIFIED target; dynamic-session requests carrying a
 * shell command, a Frida script or a §75 prohibited action are
 * refused AND audited (MOBILE_DYNAMIC_ACTION_BLOCKED); an unapproved
 * instrumentation request is BLOCKED; source artifacts are
 * OWNER/ADMIN/SECURITY_ENGINEER + audited per access.
 */

const owner = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const analyst = { id: "u-4", email: "a@example.com", organizationId: "org-1", role: "ANALYST" as const };
const viewer = { id: "u-3", email: "v@example.com", organizationId: "org-1", role: "VIEWER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

interface State {
  targets: Array<Record<string, unknown>>;
  apps: Array<Record<string, unknown>>;
  builds: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  endpoints: Array<Record<string, unknown>>;
  components: Array<Record<string, unknown>>;
  deepLinks: Array<Record<string, unknown>>;
  libraries: Array<Record<string, unknown>>;
  sboms: Array<Record<string, unknown>>;
  gates: Array<Record<string, unknown>>;
  devices: Array<Record<string, unknown>>;
  modules: Array<Record<string, unknown>>;
  sessions: Array<Record<string, unknown>>;
  traffic: Array<Record<string, unknown>>;
  switches: Array<Record<string, unknown>>;
  scopes: Array<Record<string, unknown>>;
  assessments: Array<Record<string, unknown>>;
  audits: Array<Record<string, unknown>>;
}

const HASH = FIXTURE_BUILD_HASH;

function freshState(): State {
  return {
    targets: [
      { id: "t-mob", workspaceId: "ws-1", name: "example-app", type: "MOBILE_APP", value: "com.example.app", verified: true, status: "VERIFIED" },
    ],
    apps: [{
      id: "app-1", workspaceId: "ws-1", targetId: "t-mob", name: "Example App", platform: "ANDROID",
      packageName: "com.example.app", bundleId: null, environment: "PRODUCTION", criticality: "HIGH",
      status: "REGISTERED", createdAt: new Date(0),
    }],
    builds: [{
      id: "build-1", workspaceId: "ws-1", applicationId: "app-1", versionName: "1.2", versionCode: 102,
      buildNumber: null, artifactHash: HASH, artifactFormat: "APK", artifactReference: null,
      artifactSizeBytes: 4096n, signingMetadata: { subject: "CN=Android Debug" },
      analysisArtifacts: { manifestXml: "<manifest package=\"com.example.app\"/>" },
      minOsVersion: "24", targetOsVersion: "34", status: "ANALYZED", createdAt: new Date(0),
    }],
    findings: [{
      id: "f-1", workspaceId: "ws-1", mobileBuildId: "build-1", mobileApplicationId: "app-1",
      title: "Debuggable build", severity: "HIGH", status: "OPEN", mobileFindingType: "MOBILE_MISCONFIGURATION",
      ruleId: "MOBILE_DEBUGGABLE_BUILD", owaspMobile: "M9", masvsControl: "MASVS-CODE-1", cwe: "CWE-489",
      filePath: null, mobileComponent: "application", dynamicConfirmed: false,
      crossBuildFingerprint: "c".repeat(64), sources: ["mobile-platform-analysis"], duplicateOfId: null, createdAt: new Date(0),
    }],
    endpoints: [{
      id: "ep-1", buildId: "build-1", url: "https://api.example.com/v1/home", host: "api.example.com",
      kind: "HTTPS", classification: "DISCOVERED_REFERENCE", source: "jadx", linkedAssetId: null, createdAt: new Date(0),
    }],
    components: [], deepLinks: [], libraries: [], sboms: [], gates: [],
    devices: [{
      id: "dev-1", workspaceId: "ws-1", name: "lab-emulator-1", platform: "ANDROID", deviceKind: "EMULATOR",
      osVersion: "14", capabilities: [], availability: "AVAILABLE", health: "HEALTHY",
      dedicatedNetwork: true, lastResetAt: null, status: "REGISTERED",
    }],
    modules: [{
      id: "mod-1", workspaceId: "ws-1", name: "ssl-observe", tool: "FRIDA", version: "1.0.0",
      moduleHash: "d".repeat(64), approved: true, status: "APPROVED",
    }],
    sessions: [],
    traffic: [{
      id: "traffic-1", workspaceId: "ws-1", buildId: "build-1", deviceId: "dev-1", proxyTool: "MITMPROXY",
      status: "COMPLETED", hosts: [{ host: "api.example.com", requests: 3 }], requestCount: 3,
      bytesCaptured: 1024n, sanitizationState: "SANITIZED", startedAt: null, endedAt: null,
    }],
    switches: [],
    scopes: [], assessments: [], audits: [],
  };
}

const WORKSPACES = [
  { id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date(0) },
  { id: "ws-2", organizationId: "org-2", deletedAt: null, createdAt: new Date(0) },
];

let seq = 100;
function fakePrisma(state: State) {
  const matchValue = (actual: unknown, expected: unknown): boolean => {
    if (expected === undefined) return true;
    if (expected !== null && typeof expected === "object") {
      const e = expected as Record<string, unknown>;
      if (Array.isArray(e.in)) return e.in.includes(actual);
      if (typeof e.contains === "string") return typeof actual === "string" && actual.toLowerCase().includes((e.contains as string).toLowerCase());
    }
    return actual === expected;
  };
  const match = (row: Record<string, unknown>, where: Record<string, unknown> = {}) =>
    Object.entries(where).every(([k, v]) => matchValue(row[k], v));
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
    mobileApplication: model(state.apps, "app"),
    mobileBuild: model(state.builds, "build"),
    finding: model(state.findings, "f"),
    mobileEndpoint: model(state.endpoints, "ep"),
    softwareComponent: model(state.components, "cmp"),
    mobileDeepLink: model(state.deepLinks, "dl"),
    mobileNativeLibrary: model(state.libraries, "lib"),
    softwareBillOfMaterials: model(state.sboms, "sbom"),
    qualityGateResult: model(state.gates, "gate"),
    mobileTestDevice: model(state.devices, "dev"),
    mobileInstrumentationModule: model(state.modules, "mod"),
    mobileDynamicSession: model(state.sessions, "sess"),
    mobileTrafficSession: model(state.traffic, "traf"),
    validationKillSwitch: model(state.switches, "sw"),
    scope: model(state.scopes, "scp"),
    assessment: model(state.assessments, "eng"),
  };
}

function makeService(state: State) {
  const prisma = fakePrisma(state);
  const audit = { record: async (e: Record<string, unknown>) => { state.audits.push(e); } };
  const orchestration = { startScan: async () => ({ scanId: "scan-1", status: "QUEUED" }) };
  return new MobileSecurityService(prisma as never, audit as never, orchestration as never);
}

const GOOD_ENTRIES = [
  { name: "AndroidManifest.xml", uncompressedSize: 2048, compressedSize: 900, isDirectory: false, isSymlink: false },
  { name: "classes.dex", uncompressedSize: 50000, compressedSize: 20000, isDirectory: false, isSymlink: false },
  { name: "res/values/strings.xml", uncompressedSize: 400, compressedSize: 200, isDirectory: false, isSymlink: false },
];

describe("Prompt 17 API — applications + build intake (§100/§105–§107)", () => {
  it("registers an application, creates its MOBILE_APP target and audits it", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.registerApp(owner, {
      name: "Second App", platform: "IOS", bundleId: "com.example.iosapp", environment: "PRODUCTION", criticality: "HIGH",
    });
    expect(res.status).toBe("REGISTERED");
    expect(state.targets.some((t) => t.type === "MOBILE_APP" && t.value === "com.example.iosapp" && t.verified === false)).toBe(true);
    expect(state.audits.some((a) => a.action === "MOBILE_APP_CREATED")).toBe(true);
    const again = await svc.registerApp(owner, {
      name: "Second App", platform: "IOS", bundleId: "com.example.iosapp", environment: "PRODUCTION", criticality: "HIGH",
    });
    expect(again.alreadyRegistered).toBe(true);
  });

  it("uploads a build through intake: hash identity + dedupe + audit", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.uploadBuild(owner, "app-1", {
      fileName: "app-v2.apk", versionName: "2.0", artifactSizeBytes: 22000,
      declaredSha256: "e".repeat(64), archiveEntries: GOOD_ENTRIES,
    });
    expect(res.artifactHash).toBe("e".repeat(64));
    expect(res.format).toBe("APK");
    expect(state.audits.some((a) => a.action === "MOBILE_BUILD_UPLOADED")).toBe(true);
    const dup = await svc.uploadBuild(owner, "app-1", {
      fileName: "renamed.apk", artifactSizeBytes: 22000,
      declaredSha256: "e".repeat(64), archiveEntries: GOOD_ENTRIES,
    });
    expect(dup.alreadyUploaded).toBe(true);
  });

  it("refuses archive attacks at intake (zip-slip) and hash mismatches (§107)", async () => {
    const svc = makeService(freshState());
    await expect(svc.uploadBuild(owner, "app-1", {
      fileName: "evil.apk", artifactSizeBytes: 100, declaredSha256: "f".repeat(64),
      archiveEntries: [{ name: "../escape.txt", uncompressedSize: 10, compressedSize: 10, isDirectory: false, isSymlink: false }],
    })).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.uploadBuild(owner, "app-1", {
      fileName: "app.apk", artifactSizeBytes: 100, declaredSha256: "f".repeat(64),
      archiveEntries: [{ name: "link.so", uncompressedSize: 10, compressedSize: 10, isDirectory: false, isSymlink: true, unixMode: 0o120777 }],
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("redacts the planted secret from analysis artifacts before persistence (§28/§106)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await svc.uploadBuild(owner, "app-1", {
      fileName: "app-v3.apk", artifactSizeBytes: 22000, declaredSha256: "a".repeat(64),
      archiveEntries: GOOD_ENTRIES,
      analysisArtifacts: {
        sourceSnippets: [{ path: "MainActivity.java", text: `String API_TOKEN = "${FIXTURE_SECRET_VALUE}";` }],
      },
    });
    const stored = state.builds.find((b) => b.artifactHash === "a".repeat(64));
    const visible = JSON.stringify(stored, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
    expect(visible).not.toContain(FIXTURE_SECRET_VALUE);
    expect(visible).toContain("REDACTED");
  });

  it("tenant isolation: org B sees none of org A's mobile data (§115)", async () => {
    const svc = makeService(freshState());
    await expect(svc.getApp(foreign, "app-1")).rejects.toBeInstanceOf(NotFoundException);
    await expect(svc.getBuild(foreign, "build-1")).rejects.toBeInstanceOf(NotFoundException);
    const apps = await svc.listApps(foreign);
    expect(apps.items).toHaveLength(0);
  });
});

describe("Prompt 17 API — scans, findings, endpoints (§100)", () => {
  it("starts a gated scan for a verified target and audits it", async () => {
    const state = freshState();
    const svc = makeService(state);
    state.scopes.push({ id: "scp-1", workspaceId: "ws-1", targetId: "t-mob", name: "mobile scope", rules: {} });
    state.assessments.push({
      id: "eng-1", workspaceId: "ws-1", targetId: "t-mob", scopeId: "scp-1", profile: "MOBILE_STATIC_BASELINE",
      status: "APPROVED", createdBy: "u-creator", approvedBy: "u-approver",
    });
    const res = await svc.startScan(owner, "app-1", { profile: "MOBILE_STATIC_BASELINE" });
    expect(res.scanId).toBe("scan-1");
    expect(state.scopes).toHaveLength(1);
    expect(state.assessments).toHaveLength(1);
    expect(state.audits.some((a) => a.action === "MOBILE_STATIC_SCAN_STARTED")).toBe(true);
  });

  it("scan start refuses when no pre-approved assessment exists — and mints neither scope nor assessment", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.startScan(owner, "app-1", { profile: "MOBILE_STATIC_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    state.scopes.push({ id: "scp-1", workspaceId: "ws-1", targetId: "t-mob", name: "mobile scope", rules: {} });
    await expect(svc.startScan(owner, "app-1", { profile: "MOBILE_STATIC_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    expect(state.scopes).toHaveLength(1);
    expect(state.assessments).toHaveLength(0);
  });

  it("refuses scans for unverified targets and dynamic scans for analysts", async () => {
    const state = freshState();
    state.targets[0]!.verified = false;
    const svc = makeService(state);
    await expect(svc.startScan(owner, "app-1", { profile: "MOBILE_STATIC_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    state.targets[0]!.verified = true;
    await expect(svc.startScan(analyst, "app-1", { profile: "MOBILE_DYNAMIC_CONTROLLED" })).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("serves build findings + endpoints with DISCOVERED_REFERENCE intact (§30)", async () => {
    const svc = makeService(freshState());
    const findings = await svc.listBuildFindings(owner, "build-1");
    expect(findings.items[0]?.ruleId).toBe("MOBILE_DEBUGGABLE_BUILD");
    expect(findings.items[0]?.owaspMobile).toBe("M9");
    const endpoints = await svc.listBuildEndpoints(owner, "build-1");
    expect(endpoints.items[0]?.classification).toBe("DISCOVERED_REFERENCE");
    expect(endpoints.items[0]?.linkedAssetId).toBeNull();
  });

  it("source artifacts require the artifact permission and are audited (§24/§116)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.getBuildArtifacts(analyst, "build-1")).rejects.toBeInstanceOf(ForbiddenException);
    const res = await svc.getBuildArtifacts(owner, "build-1");
    expect(res.artifactHash).toBe(HASH);
    expect(state.audits.some((a) => a.action === "MOBILE_ARTIFACT_ACCESSED")).toBe(true);
  });
});

describe("Prompt 17 API — dynamic sessions (§58/§69–§75/§110)", () => {
  const baseRequest = {
    buildId: "build-1", deviceId: "dev-1", profile: "MOBILE_DYNAMIC_CONTROLLED" as const,
    requestedActions: ["INSTALL_APPROVED_BUILD", "COLLECT_LOGS"], moduleIds: ["mod-1"],
    instrumentationApproved: true, trafficCapture: false,
  };

  it("approves a governed session: approved module + lab device + instrumentation approval (§73)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.createDynamicSession(owner, "app-1", baseRequest);
    expect(res.status).toBe("APPROVED");
    expect(state.audits.some((a) => a.action === "MOBILE_DYNAMIC_SESSION_APPROVED")).toBe(true);
  });

  it("BLOCKS a session without instrumentation approval and audits the block (§110)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.createDynamicSession(owner, "app-1", { ...baseRequest, instrumentationApproved: false }))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(state.sessions.some((s) => s.status === "BLOCKED")).toBe(true);
    expect(state.audits.some((a) => a.action === "MOBILE_DYNAMIC_ACTION_BLOCKED")).toBe(true);
  });

  it("REJECTS shell commands, Frida scripts and prohibited actions — refused + audited (§75/§110)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.createDynamicSession(owner, "app-1", { ...baseRequest, shellCommand: "adb shell id" }))
      .rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.createDynamicSession(owner, "app-1", { ...baseRequest, scriptBody: "Java.perform(() => {})" }))
      .rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.createDynamicSession(owner, "app-1", { ...baseRequest, requestedActions: ["SMS_INTERCEPTION"] }))
      .rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.createDynamicSession(owner, "app-1", { ...baseRequest, requestedActions: ["PINNING_BYPASS_AUTOMATION"] }))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(state.audits.filter((a) => a.action === "MOBILE_DYNAMIC_ACTION_BLOCKED").length).toBeGreaterThanOrEqual(4);
    expect(state.sessions.every((s) => s.status === "BLOCKED")).toBe(true);
  });

  it("an active kill switch blocks dynamic sessions (§92)", async () => {
    const state = freshState();
    state.switches.push({ id: "sw-1", level: "GLOBAL", active: true, organizationId: null, workspaceId: null, scopeRef: null });
    const svc = makeService(state);
    await expect(svc.createDynamicSession(owner, "app-1", baseRequest)).rejects.toBeInstanceOf(BadRequestException);
  });

  it("registers lab devices (admin only) and serves sanitized traffic metadata (§98/§99)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.registerDevice(analyst, { name: "emu-2", platform: "ANDROID", deviceKind: "EMULATOR", dedicatedNetwork: true, capabilities: [] }))
      .rejects.toBeInstanceOf(ForbiddenException);
    const dev = await svc.registerDevice(owner, { name: "emu-2", platform: "ANDROID", deviceKind: "EMULATOR", dedicatedNetwork: true, capabilities: [] });
    expect(dev.status).toBe("REGISTERED");
    const traffic = await svc.getTrafficSession(owner, "traffic-1");
    expect(traffic.hosts).toEqual([{ host: "api.example.com", requests: 3 }]);
    expect(JSON.stringify(traffic)).not.toContain("body");
    expect(state.audits.some((a) => a.action === "MOBILE_TRAFFIC_ACCESSED")).toBe(true);
    const tools = await svc.listTools(viewer);
    expect(tools.items.find((t) => t.slug === "frida")?.health).toBe("DISABLED");
    expect(tools.items.find((t) => t.slug === "objection")?.health).toBe("APPROVAL_REQUIRED");
  });
});
