import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { FAKE_BINARY_TOKEN, FIXTURE_ELF_HARDENED, FIXTURE_ELF_SHA256 } from "@zerosweep/security-sdk";
import { BinarySecurityService } from "./binary-security.service";

/**
 * Prompt 18 §92–§119 API discipline: artifacts are tenant-isolated
 * and identified by SHA-256 (dedupe by hash); format comes from
 * MAGIC BYTES (a spoofed name is reported as the real format); raw
 * artifact access is audited per read (§84); scans are gated on a
 * VERIFIED target; debug-session requests carrying command/script
 * content, prohibited operations, a PRODUCTION environment, or a
 * self-approval are refused/BLOCKED + audited
 * (BINARY_DEBUG_ACTION_BLOCKED, §113/§114); the planted FAKE token
 * exists in NO record.
 */

const owner = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const engineer = { id: "u-5", email: "e@example.com", organizationId: "org-1", role: "SECURITY_ENGINEER" as const };
const analyst = { id: "u-4", email: "a@example.com", organizationId: "org-1", role: "ANALYST" as const };
const viewer = { id: "u-3", email: "v@example.com", organizationId: "org-1", role: "VIEWER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

interface State {
  targets: Array<Record<string, unknown>>;
  artifacts: Array<Record<string, unknown>>;
  sections: Array<Record<string, unknown>>;
  functions: Array<Record<string, unknown>>;
  imports: Array<Record<string, unknown>>;
  exportsRows: Array<Record<string, unknown>>;
  symbols: Array<Record<string, unknown>>;
  dependencies: Array<Record<string, unknown>>;
  profiles: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  components: Array<Record<string, unknown>>;
  sboms: Array<Record<string, unknown>>;
  diffs: Array<Record<string, unknown>>;
  sessions: Array<Record<string, unknown>>;
  switches: Array<Record<string, unknown>>;
  scopes: Array<Record<string, unknown>>;
  assessments: Array<Record<string, unknown>>;
  audits: Array<Record<string, unknown>>;
}

const SEGMENT_B64 = FIXTURE_ELF_HARDENED.toString("base64");

function freshState(): State {
  return {
    targets: [
      { id: "t-bin", workspaceId: "ws-1", name: "app-hardened", type: "BINARY", value: "app-hardened", verified: true, status: "VERIFIED" },
      { id: "t-bin2", workspaceId: "ws-1", name: "app-v2", type: "BINARY", value: "app-v2", verified: true, status: "VERIFIED" },
    ],
    artifacts: [
      {
        id: "bin-1", workspaceId: "ws-1", targetId: "t-bin", name: "app-hardened", source: "UPLOAD",
        artifactReference: "fixture://binary-1", sha256: FIXTURE_ELF_SHA256, sha1: null,
        sizeBytes: BigInt(FIXTURE_ELF_HARDENED.length), format: "ELF", architecture: "x86-64",
        bitness: 64, endianness: "LE", environment: "PRODUCTION", status: "ANALYZED",
        analysisArtifacts: { headerSegmentBase64: SEGMENT_B64 }, createdAt: new Date(0),
      },
      {
        id: "bin-2", workspaceId: "ws-1", targetId: "t-bin2", name: "app-v2", source: "UPLOAD",
        artifactReference: "fixture://binary-2", sha256: "b".repeat(64), sha1: null,
        sizeBytes: 2048n, format: "ELF", architecture: "x86-64",
        bitness: 64, endianness: "LE", environment: "LAB", status: "ANALYZED",
        analysisArtifacts: {}, createdAt: new Date(0),
      },
    ],
    sections: [{ id: "sec-1", artifactId: "bin-1", name: ".text", type: "SHT-1", size: 512n, permissions: "RX", entropy: 6.1, source: "ghidra" }],
    functions: [
      { id: "fn-1", artifactId: "bin-1", name: "main", address: "0x1040", size: 48, callingConvention: "__stdcall", fingerprint: "fn:main:9f2c", referencesRiskyApi: [], confidence: 0.95, source: "ghidra" },
      { id: "fn-2", artifactId: "bin-2", name: "main", address: "0x1040", size: 48, callingConvention: "__stdcall", fingerprint: "fn:main:9f2c", referencesRiskyApi: [], confidence: 0.95, source: "ghidra" },
      { id: "fn-3", artifactId: "bin-2", name: "new_helper", address: "0x1300", size: 24, callingConvention: null, fingerprint: "fn:new_helper:aa11", referencesRiskyApi: [], confidence: 0.8, source: "ghidra" },
    ],
    imports: [], exportsRows: [], symbols: [],
    dependencies: [
      { id: "dep-1", artifactId: "bin-1", library: "z", version: "1.2.11", purl: "pkg:generic/z@1.2.11", cpe: null, sourceKind: "DETECTED_LINKED", confidence: 0.8, source: "binary-platform-analysis" },
      { id: "dep-2", artifactId: "bin-2", library: "z", version: "1.2.11", purl: "pkg:generic/z@1.2.11", cpe: null, sourceKind: "DETECTED_LINKED", confidence: 0.8, source: "binary-platform-analysis" },
    ],
    profiles: [{ id: "hp-1", artifactId: "bin-1", profile: [{ name: "NX", status: "ENABLED", evidence: "GNU_STACK RW", source: "checksec" }], assessedAt: new Date(0) }],
    findings: [{
      id: "f-1", workspaceId: "ws-1", binaryArtifactId: "bin-1", title: "Embedded secret candidate", severity: "HIGH",
      status: "OPEN", binaryFindingType: "BINARY_SECRET", ruleId: "BINARY_EMBEDDED_SECRET", cwe: "CWE-798",
      cve: null, binaryComponent: ".rodata", binaryReachability: "UNKNOWN", binaryFingerprint: "bin:fp1",
      staticConfidence: "HIGH", sources: ["binary-platform-analysis"], duplicateOfId: null, createdAt: new Date(0),
    }],
    components: [], sboms: [], diffs: [], sessions: [], switches: [], scopes: [], assessments: [], audits: [],
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
    findUnique: async (args: { where: Record<string, unknown> }) => {
      if (typeof args.where.id === "string") return rows.find((r) => r.id === args.where.id) ?? null;
      if (typeof args.where.artifactId === "string") return rows.find((r) => r.artifactId === args.where.artifactId) ?? null;
      return null;
    },
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
    binaryArtifact: model(state.artifacts, "bin"),
    binarySection: model(state.sections, "sec"),
    binaryFunction: model(state.functions, "fn"),
    binaryImport: model(state.imports, "imp"),
    binaryExport: model(state.exportsRows, "exp"),
    binarySymbol: model(state.symbols, "sym"),
    binaryDependency: model(state.dependencies, "dep"),
    binaryHardeningProfile: model(state.profiles, "hp"),
    binaryDiff: model(state.diffs, "diff"),
    binaryDebugSession: model(state.sessions, "sess"),
    finding: model(state.findings, "f"),
    softwareComponent: model(state.components, "cmp"),
    softwareBillOfMaterials: model(state.sboms, "sbom"),
    validationKillSwitch: model(state.switches, "sw"),
    scope: model(state.scopes, "scp"),
    assessment: model(state.assessments, "eng"),
  };
}

function makeService(state: State) {
  const prisma = fakePrisma(state);
  const audit = { record: async (e: Record<string, unknown>) => { state.audits.push(e); } };
  const orchestration = { startScan: async () => ({ scanId: "scan-1", status: "QUEUED" }) };
  return new BinarySecurityService(prisma as never, audit as never, orchestration as never);
}

describe("Prompt 18 API — artifact intake (§92/§97–§102)", () => {
  it("registers an artifact: magic-byte format wins over the file name, hash dedupes, upload audited", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.registerArtifact(owner, {
      name: "report.pdf", // §102 spoof: the NAME lies, the bytes are ELF
      source: "UPLOAD", sha256: "c".repeat(64), sizeBytes: FIXTURE_ELF_HARDENED.length,
      headerSegmentBase64: SEGMENT_B64, environment: "PRODUCTION",
    });
    expect(res.format).toBe("ELF");
    expect(state.audits.some((a) => a.action === "BINARY_UPLOADED")).toBe(true);
    const dup = await svc.registerArtifact(owner, {
      name: "renamed.bin", source: "UPLOAD", sha256: "c".repeat(64), sizeBytes: 10, environment: "PRODUCTION",
    });
    expect(dup.alreadyRegistered).toBe(true);
  });

  it("refuses content with no recognized magic bytes when a segment is supplied (§5)", async () => {
    const svc = makeService(freshState());
    await expect(svc.registerArtifact(owner, {
      name: "mystery.bin", source: "UPLOAD", sha256: "d".repeat(64), sizeBytes: 64,
      headerSegmentBase64: Buffer.from("not a binary at all........").toString("base64"),
      environment: "PRODUCTION",
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("tenant isolation: org B cannot read org A's artifact (§119)", async () => {
    const svc = makeService(freshState());
    await expect(svc.getArtifact(foreign, "bin-1")).rejects.toBeInstanceOf(NotFoundException);
    await expect(svc.listFunctions(foreign, "bin-1")).rejects.toBeInstanceOf(NotFoundException);
  });

  it("artifact detail audits every raw access (§84) and never exposes the planted token", async () => {
    const state = freshState();
    const svc = makeService(state);
    const detail = await svc.getArtifact(owner, "bin-1");
    expect(detail.sha256).toBe(FIXTURE_ELF_SHA256);
    expect(state.audits.some((a) => a.action === "BINARY_ARTIFACT_ACCESSED")).toBe(true);
    const json = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? String(x) : x));
    expect(json(detail)).not.toContain(FAKE_BINARY_TOKEN);
    expect(json(state)).not.toContain(FAKE_BINARY_TOKEN);
  });

  it("the function explorer requires VIEW_BINARY_DECOMPILATION (analyst refused) and audits access", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.listFunctions(analyst, "bin-1")).rejects.toBeInstanceOf(ForbiddenException);
    const res = await svc.listFunctions(engineer, "bin-1");
    expect(res.items.some((f) => f.name === "main")).toBe(true);
    expect(res.bounded).toBe(true);
    expect(state.audits.some((a) => a.action === "BINARY_DECOMPILATION_ACCESSED")).toBe(true);
  });

  it("hardening view returns observations, and tools report honest governed states (§95/§96)", async () => {
    const svc = makeService(freshState());
    const hardening = await svc.getHardening(owner, "bin-1");
    expect((hardening.profile as Array<{ name: string }>).some((h) => h.name === "NX")).toBe(true);
    const tools = await svc.listTools(owner);
    const bySlug = new Map(tools.items.map((t) => [t.slug, t]));
    expect(bySlug.get("ida")?.health).toBe("NOT_CONFIGURED");
    expect(bySlug.get("binary-ninja")?.health).toBe("NOT_CONFIGURED");
    expect(bySlug.get("gdb")?.health).toBe("DISABLED");
    expect(bySlug.get("pwndbg")?.health).toBe("APPROVAL_REQUIRED");
    expect(bySlug.get("cutter")?.health).toBe("ANALYST_TOOL");
  });
});

describe("Prompt 18 API — scans, diffs (§53–§55/§92)", () => {
  it("starts a scan only for a VERIFIED target through the gated path", async () => {
    const state = freshState();
    const svc = makeService(state);
    state.scopes.push({ id: "scp-1", workspaceId: "ws-1", targetId: "t-bin", name: "binary scope", rules: {} });
    state.assessments.push({
      id: "eng-1", workspaceId: "ws-1", targetId: "t-bin", scopeId: "scp-1", profile: "BINARY_BASELINE",
      status: "APPROVED", createdBy: "u-creator", approvedBy: "u-approver",
    });
    const res = await svc.startScan(owner, "bin-1", { profile: "BINARY_BASELINE" });
    expect(res.scanId).toBe("scan-1");
    expect(state.scopes).toHaveLength(1);
    expect(state.assessments).toHaveLength(1);
    expect(state.audits.some((a) => a.action === "BINARY_STATIC_SCAN_STARTED")).toBe(true);
    state.targets[0]!.verified = false;
    await expect(svc.startScan(owner, "bin-1", { profile: "BINARY_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("scan start refuses when no pre-approved assessment exists — and mints neither scope nor assessment", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.startScan(owner, "bin-1", { profile: "BINARY_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    state.scopes.push({ id: "scp-1", workspaceId: "ws-1", targetId: "t-bin", name: "binary scope", rules: {} });
    await expect(svc.startScan(owner, "bin-1", { profile: "BINARY_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    expect(state.scopes).toHaveLength(1);
    expect(state.assessments).toHaveLength(0);
  });

  it("viewer cannot upload or scan (§94)", async () => {
    const svc = makeService(freshState());
    await expect(svc.registerArtifact(viewer, {
      name: "x", source: "UPLOAD", sha256: "e".repeat(64), sizeBytes: 1, environment: "PRODUCTION",
    })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(svc.startScan(viewer, "bin-1", { profile: "BINARY_BASELINE" })).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("creates a cross-build diff over persisted inventories and audits it (§53)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.createDiff(owner, { baseArtifactId: "bin-1", targetArtifactId: "bin-2" });
    expect(res.summary).toBeDefined();
    expect(state.diffs).toHaveLength(1);
    expect(state.audits.some((a) => a.action === "BINARY_DIFF_CREATED")).toBe(true);
    const fetched = await svc.getDiff(owner, res.id);
    expect(fetched.baseArtifactId).toBe("bin-1");
  });
});

describe("Prompt 18 API — debug governance (§64–§74/§113–§115)", () => {
  it("a LAB session request is recorded as REQUESTED and audited", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.createDebugSession(engineer, "bin-2", {
      operations: [{ operation: "START_APPROVED_FIXTURE" }], networkPolicy: "NO_NETWORK",
    });
    expect(res.status).toBe("REQUESTED");
    expect(state.audits.some((a) => a.action === "BINARY_DEBUG_REQUESTED")).toBe(true);
  });

  it("a PRODUCTION artifact's debug request is BLOCKED by policy (§113)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.createDebugSession(engineer, "bin-1", {
      operations: [{ operation: "START_APPROVED_FIXTURE" }],
    });
    expect(res.status).toBe("BLOCKED");
    expect(state.audits.some((a) => a.action === "BINARY_DEBUG_ACTION_BLOCKED")).toBe(true);
  });

  it("command-carrying requests are BLOCKED + audited and the command is never persisted (§114)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.createDebugSession(engineer, "bin-2", {
      operations: [{ operation: "START_APPROVED_FIXTURE" }],
      gdbCommand: "shell rm -rf /",
    });
    expect(res.status).toBe("BLOCKED");
    expect(state.audits.some((a) => a.action === "BINARY_DEBUG_ACTION_BLOCKED")).toBe(true);
    expect(JSON.stringify(state.sessions)).not.toContain("rm -rf");
  });

  it("prohibited operations are BLOCKED + audited (§68)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.createDebugSession(engineer, "bin-2", {
      operations: [{ operation: "CREDENTIAL_EXTRACTION" }],
    });
    expect(res.status).toBe("BLOCKED");
    expect(state.audits.some((a) => a.action === "BINARY_DEBUG_ACTION_BLOCKED")).toBe(true);
  });

  it("approval enforces separation of duties: requester cannot self-approve (§67)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const created = await svc.createDebugSession(engineer, "bin-2", {
      operations: [{ operation: "START_APPROVED_FIXTURE" }],
    });
    // The engineer requested; the OWNER (different user, approver
    // role) approves — allowed.
    const approved = await svc.approveDebugSession(owner, created.id, { decision: "APPROVE" });
    expect(approved.status).toBe("APPROVED");
    expect(state.audits.some((a) => a.action === "BINARY_DEBUG_APPROVED")).toBe(true);
    // Self-approval: owner requests a session, then tries to approve it.
    const own = await svc.createDebugSession(owner, "bin-2", {
      operations: [{ operation: "START_APPROVED_FIXTURE" }],
    });
    await expect(svc.approveDebugSession(owner, own.id, { decision: "APPROVE" })).rejects.toBeInstanceOf(BadRequestException);
    // Analysts cannot approve at all (§94).
    await expect(svc.approveDebugSession(analyst, own.id, { decision: "APPROVE" })).rejects.toBeInstanceOf(ForbiddenException);
  });
});
