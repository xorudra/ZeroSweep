import { BadRequestException, NotFoundException } from "@nestjs/common";
import { BURP_ISSUES_XML, HAR_EXPORT, ZAP_ALERTS, hashScopeSnapshot } from "@dsrclone/security-sdk";
import { ScanHttpHistoryController, ScannersController } from "./scanners.controller";
import { ScannersService } from "./scanners.service";
import { ROLES_KEY } from "../../common/decorators/auth.decorators";

/**
 * Prompt 8 API guarantees (§15–§21, §54–§71):
 *  - instances store references, never URLs or secret values; URL-shaped
 *    endpoint references are rejected at the boundary (SSRF, §71);
 *  - tenant isolation: org B never sees org A's instances (§69);
 *  - health checks report honestly (MISCONFIGURED when the reference
 *    does not resolve server-side — no fake HEALTHY);
 *  - approvals require verified target + approved assessment, bind to a
 *    scope hash, expire, and revoke with audit (§40–§43);
 *  - imports are format/size-guarded and merge by canonical fingerprint;
 *  - raw-evidence access is OWNER/ADMIN and always audited (§60).
 */

const owner = { id: "u-1", email: "rudra@example.com", organizationId: "org-1", role: "OWNER" } as never;
const otherOrgAdmin = { id: "u-9", email: "other@example.com", organizationId: "org-2", role: "ADMIN" } as never;

const SCOPE_RULES = { includeHosts: ["example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [443], allowedPaths: [], excludedPaths: [] };

function makeWorld() {
  const auditCalls: Array<{ action: string; metadata?: Record<string, unknown> }> = [];
  const audit = { record: async (e: { action: string; metadata?: Record<string, unknown> }) => { auditCalls.push(e); } };
  const db = {
    instances: [] as Record<string, unknown>[],
    approvals: [] as Record<string, unknown>[],
    assets: [] as Record<string, unknown>[],
    endpoints: [] as Record<string, unknown>[],
    transactions: [] as Record<string, unknown>[],
    findings: [] as Record<string, unknown>[],
    evidence: [] as Record<string, unknown>[],
    history: [] as Record<string, unknown>[],
    sessionProfiles: [] as Record<string, unknown>[],
    assessment: {
      id: "asmt-1", workspaceId: "ws-1", status: "APPROVED", profile: "WEB_COMPREHENSIVE", scopeId: "scope-1",
      targetId: "t-1",
      target: { id: "t-1", verified: true },
      scope: { rules: SCOPE_RULES },
    } as Record<string, unknown> | null,
    scan: { id: "scan-1", workspaceId: "ws-1", assessmentId: "asmt-1" } as Record<string, unknown> | null,
  };
  let seq = 0;
  const nid = (p: string) => `${p}-${++seq}`;
  const prisma = {
    workspace: {
      findFirst: async ({ where }: never) => {
        const w = where as { id?: string; organizationId: string };
        if (w.organizationId !== "org-1") return null;
        return { id: w.id ?? "ws-1", organizationId: "org-1" };
      },
    },
    tool: { findUnique: async ({ where }: never) => ({ id: `tool-${(where as { slug: string }).slug}`, slug: (where as { slug: string }).slug }) },
    scannerInstance: {
      findMany: async ({ where }: never) => db.instances.filter((i) => i.organizationId === (where as { organizationId: string }).organizationId)
        .map((i) => ({ ...i, tool: { slug: i.toolSlug } })),
      findFirst: async ({ where }: never) => {
        const w = where as { id: string; organizationId: string };
        const row = db.instances.find((i) => i.id === w.id && i.organizationId === w.organizationId);
        return row ? { ...row, tool: { slug: row.toolSlug } } : null;
      },
      create: async ({ data }: never) => {
        const d = data as Record<string, unknown>;
        const row = { id: nid("inst"), healthStatus: "NOT_CONFIGURED", version: null, licenseState: null, lastHealthCheckAt: null, lastHealthDetail: null, detectedCapabilities: [], enabled: true, createdAt: new Date(), updatedAt: new Date(), ...d };
        db.instances.push(row);
        return { ...row, tool: { slug: (d as { toolId: string }).toolId.replace("tool-", "") } };
      },
      update: async ({ where, data }: never) => {
        const row = db.instances.find((i) => i.id === (where as { id: string }).id)!;
        Object.assign(row, data);
        return { ...row, tool: { slug: row.toolSlug } };
      },
      delete: async ({ where }: never) => { db.instances = db.instances.filter((i) => i.id !== (where as { id: string }).id); },
    },
    assessment: { findFirst: async () => db.assessment },
    scan: {
      findFirst: async ({ where }: never) => {
        const w = where as { id: string; assessmentId?: string };
        if (!db.scan || db.scan.id !== w.id) return null;
        if (w.assessmentId && db.scan.assessmentId !== w.assessmentId) return null;
        return { ...db.scan, assessment: { targetId: "t-1", target: { id: "t-1", verified: true }, scope: { rules: SCOPE_RULES } } };
      },
    },
    scanApproval: {
      create: async ({ data }: never) => { const row = { id: nid("appr"), createdAt: new Date(), updatedAt: new Date(), ...(data as object) }; db.approvals.push(row); return row; },
      findMany: async ({ where }: never) => db.approvals.filter((a) => a.workspaceId === (where as { workspaceId: string }).workspaceId),
      findFirst: async ({ where }: never) => db.approvals.find((a) => a.id === (where as { id: string }).id) ?? null,
      findUnique: async ({ where }: never) => db.approvals.find((a) => a.id === (where as { id: string }).id) ?? null,
      update: async ({ where, data }: never) => { const row = db.approvals.find((a) => a.id === (where as { id: string }).id)!; Object.assign(row, data); return row; },
    },
    asset: {
      findFirst: async ({ where }: never) => db.assets.find((a) => a.targetId === (where as { targetId: string }).targetId && a.host === (where as { host: string }).host) ?? null,
      create: async ({ data }: never) => { const row = { id: nid("asset"), ...(data as object) }; db.assets.push(row); return row; },
    },
    endpoint: {
      findFirst: async ({ where }: never) => db.endpoints.find((e) => e.assetId === (where as { assetId: string }).assetId && e.url === (where as { url: string }).url) ?? null,
      create: async ({ data }: never) => { const row = { id: nid("ep"), sources: [], ...(data as object) }; db.endpoints.push(row); return row; },
      update: async ({ where, data }: never) => { const row = db.endpoints.find((e) => e.id === (where as { id: string }).id)!; Object.assign(row, data); return row; },
    },
    httpTransaction: {
      create: async ({ data }: never) => { const row = { id: nid("tx"), ...(data as object) }; db.transactions.push(row); return row; },
      findMany: async () => db.transactions,
      findFirst: async ({ where }: never) => db.transactions.find((t) => t.id === (where as { id: string }).id) ?? null,
    },
    webSocketEndpoint: { upsert: async () => ({}) },
    finding: {
      findFirst: async ({ where }: never) => db.findings.find((f) => f.scanId === (where as { scanId: string }).scanId && f.fingerprint === (where as { fingerprint: string }).fingerprint) ?? null,
      create: async ({ data }: never) => { const row = { id: nid("find"), sources: [], ...(data as object) }; db.findings.push(row); return row; },
      update: async ({ where, data }: never) => { const row = db.findings.find((f) => f.id === (where as { id: string }).id)!; Object.assign(row, data); return row; },
    },
    findingEvidence: { create: async ({ data }: never) => { db.evidence.push(data as Record<string, unknown>); return data; } },
    findingHistory: { create: async ({ data }: never) => { db.history.push(data as Record<string, unknown>); return data; } },
    sessionProfile: {
      findMany: async () => db.sessionProfiles,
      create: async ({ data }: never) => { const row = { id: nid("sp"), ...(data as object) }; db.sessionProfiles.push(row); return row; },
      findFirst: async ({ where }: never) => db.sessionProfiles.find((p) => p.id === (where as { id: string }).id) ?? null,
    },
    authenticationProfile: { create: async ({ data }: never) => ({ id: nid("authp"), ...(data as object) }) },
  };
  const service = new ScannersService(prisma as never, audit as never);
  const ctrl = new ScannersController(service, prisma as never);
  const history = new ScanHttpHistoryController(prisma as never, audit as never);
  return { db, auditCalls, service, ctrl, history, prisma };
}

describe("scanner instances (§15–§17, §54/§55)", () => {
  it("rejects URL-shaped endpoint references at the boundary (SSRF by construction)", async () => {
    const { ctrl, service } = makeWorld();
    await expect(Promise.resolve().then(() => ctrl.createInstance(owner, { name: "ZAP", toolSlug: "owasp-zap", endpointReference: "https://zap.internal:8080" }))).rejects.toThrow();
    await expect(service.createInstance(owner, { name: "ZAP", toolSlug: "owasp-zap", endpointReference: "169.254.169.254", deploymentType: "MANAGED_DAEMON" })).rejects.toBeInstanceOf(BadRequestException);
    await expect(service.createInstance(owner, { name: "ZAP", toolSlug: "owasp-zap", endpointReference: "zap.internal", deploymentType: "MANAGED_DAEMON" })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("registers an instance with reference names only — no URL, no secret value anywhere", async () => {
    const { ctrl, auditCalls } = makeWorld();
    const view = await ctrl.createInstance(owner, {
      name: "ZAP daemon", toolSlug: "owasp-zap", endpointReference: "ZAP_DAEMON_PROD",
      credentialReference: "ZAP_API_KEY_PROD", deploymentType: "MANAGED_DAEMON",
    });
    expect(view.endpointReference).toBe("ZAP_DAEMON_PROD");
    expect(view.credentialReference).toBe("ZAP_API_KEY_PROD");
    expect(view.healthStatus).toBe("NOT_CONFIGURED");
    expect(JSON.stringify(view)).not.toContain("http://");
    expect(JSON.stringify(view)).not.toContain("https://");
    expect(auditCalls.some((a) => a.action === "SCANNER_INSTANCE_REGISTERED")).toBe(true);
  });

  it("rejects capabilities beyond the product ceiling (§14)", async () => {
    const { service } = makeWorld();
    await expect(service.createInstance(owner, {
      name: "ZAP", toolSlug: "owasp-zap", endpointReference: "ZAP_DAEMON_PROD",
      deploymentType: "MANAGED_DAEMON", declaredCapabilities: ["TELEPORTATION"],
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("isolates tenants: org B sees none of org A's instances (§69)", async () => {
    const { ctrl, service } = makeWorld();
    const view = await ctrl.createInstance(owner, { name: "ZAP", toolSlug: "owasp-zap", endpointReference: "ZAP_DAEMON_PROD" });
    expect(await ctrl.listInstances(otherOrgAdmin)).toHaveLength(0);
    await expect(service.updateInstance(otherOrgAdmin, view.id, { enabled: false })).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.healthCheckInstance(otherOrgAdmin, view.id)).rejects.toBeInstanceOf(NotFoundException);
  });

  it("health-check reports MISCONFIGURED when the reference does not resolve server-side — never a fake HEALTHY", async () => {
    const { ctrl, service } = makeWorld();
    const view = await ctrl.createInstance(owner, { name: "ZAP", toolSlug: "owasp-zap", endpointReference: "ZAP_NOT_IN_SERVER_CONFIG" });
    const health = await service.healthCheckInstance(owner, view.id);
    expect(health.healthStatus).toBe("MISCONFIGURED");
  });

  it("write routes are OWNER/ADMIN only", () => {
    expect(Reflect.getMetadata(ROLES_KEY, ScannersController.prototype.createInstance)).toEqual(["OWNER", "ADMIN"]);
    expect(Reflect.getMetadata(ROLES_KEY, ScannersController.prototype.healthCheck)).toEqual(["OWNER", "ADMIN"]);
    expect(Reflect.getMetadata(ROLES_KEY, ScanHttpHistoryController.prototype.raw)).toEqual(["OWNER", "ADMIN"]);
  });
});

describe("session profiles (§18–§20)", () => {
  it("rejects bodies carrying secret values or scripts (strict schema)", async () => {
    const { ctrl } = makeWorld();
    await expect(ctrl.createSessionProfile(owner, { name: "S", type: "AUTHENTICATED", password: "hunter2" })).rejects.toThrow();
    await expect(ctrl.createSessionProfile(owner, { name: "S", type: "AUTHENTICATED", script: "login()" })).rejects.toThrow();
  });
  it("stores metadata + credential reference only", async () => {
    const { ctrl } = makeWorld();
    const profile = await ctrl.createSessionProfile(owner, {
      name: "Authenticated", type: "AUTHENTICATED", credentialReference: "APP_SESSION_PROD",
      validation: { authenticatedUrl: "https://example.com/account", expectedStatus: 200 },
    }) as Record<string, unknown>;
    expect(profile.credentialReference).toBe("APP_SESSION_PROD");
    expect(JSON.stringify(profile)).not.toContain("hunter2");
  });
});

describe("active-scan approvals (§40–§43)", () => {
  it("refuses approval when the target is unverified or the assessment unapproved", async () => {
    const { service, db } = makeWorld();
    (db.assessment!.target as { verified: boolean }).verified = false;
    await expect(service.grantApproval(owner, { assessmentId: "asmt-1", capability: "ACTIVE_WEB_SCANNING" })).rejects.toBeInstanceOf(BadRequestException);
    (db.assessment!.target as { verified: boolean }).verified = true;
    db.assessment!.status = "DRAFT";
    await expect(service.grantApproval(owner, { assessmentId: "asmt-1", capability: "ACTIVE_WEB_SCANNING" })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("grants against a scope snapshot hash, and revocation is audited", async () => {
    const { service, ctrl, auditCalls } = makeWorld();
    const row = await service.grantApproval(owner, { assessmentId: "asmt-1", capability: "ACTIVE_WEB_SCANNING" }) as Record<string, unknown>;
    expect(row.scopeSnapshotHash).toBe(hashScopeSnapshot(SCOPE_RULES));
    expect(row.status).toBe("ACTIVE");
    const revoked = await service.revokeApproval(owner, row.id as string) as Record<string, unknown>;
    expect(revoked.status).toBe("REVOKED");
    expect(auditCalls.some((a) => a.action === "ACTIVE_SCAN_APPROVAL_GRANTED")).toBe(true);
    expect(auditCalls.some((a) => a.action === "ACTIVE_SCAN_APPROVAL_REVOKED")).toBe(true);
    void ctrl;
  });

  it("refuses an expiry in the past (§42)", async () => {
    const { service } = makeWorld();
    await expect(service.grantApproval(owner, { assessmentId: "asmt-1", capability: "ACTIVE_WEB_SCANNING", expiresAt: "2020-01-01T00:00:00.000Z" })).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe("imports (§32/§61–§63)", () => {
  it("imports Burp XML issues + traffic; a repeat import merges by canonical fingerprint", async () => {
    const { service, db } = makeWorld();
    const first = await service.importExport(owner, { format: "burp-xml", payload: BURP_ISSUES_XML, scanId: "scan-1" });
    expect(first.findings.created).toBe(2);
    expect(first.transactions).toBe(1);
    const second = await service.importExport(owner, { format: "burp-xml", payload: BURP_ISSUES_XML, scanId: "scan-1" });
    expect(second.findings.created).toBe(0);
    expect(second.findings.merged).toBe(2);
    expect(db.findings).toHaveLength(2);
    // Imported evidence is redacted: the fixture's fake Burp secrets never persist.
    expect(JSON.stringify(db.evidence)).not.toContain("fixture-burp-secret");
    expect(JSON.stringify(db.evidence)).not.toContain("fixture-burp-token");
  });

  it("rejects XXE payloads before parsing", async () => {
    const { service } = makeWorld();
    const xxe = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><issues><issue><name>&xxe;</name></issue></issues>`;
    await expect(service.importExport(owner, { format: "burp-xml", payload: xxe, scanId: "scan-1" })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("HAR imports produce endpoints + transactions and ZERO findings", async () => {
    const { service } = makeWorld();
    const res = await service.importExport(owner, { format: "har", payload: JSON.stringify(HAR_EXPORT), scanId: "scan-1" });
    expect(res.findings.total).toBe(0);
    expect(res.endpoints).toBe(2);
    expect(res.transactions).toBe(2);
  });

  it("ZAP JSON alerts import as normalized findings", async () => {
    const { service } = makeWorld();
    const res = await service.importExport(owner, { format: "zap-json", payload: JSON.stringify(ZAP_ALERTS), scanId: "scan-1" });
    expect(res.findings.created).toBe(2); // CSP + SameSite; the informational plugin note is an observation
  });
});

describe("HTTP history + raw evidence (§59/§60)", () => {
  it("raw access returns references + hashes and writes the audit record", async () => {
    const { history, db, auditCalls } = makeWorld();
    db.transactions.push({
      id: "tx-1", scanId: "scan-1", workspaceId: "ws-1", method: "GET", url: "https://example.com/",
      host: "example.com", source: "owasp-zap", requestHash: "abc", responseHash: "def",
      requestArtifactRef: "scans/scan-1/executions/e1/owasp-zap.json#tx-0", responseArtifactRef: "scans/scan-1/executions/e1/owasp-zap.json#tx-0",
      requestRedacted: "GET / HTTP/1.1", responseRedacted: "HTTP/1.1 200 OK",
    });
    const out = await history.raw(owner, "scan-1", "tx-1") as Record<string, unknown>;
    expect(out.requestHash).toBe("abc");
    expect(auditCalls.some((a) => a.action === "RAW_EVIDENCE_ACCESSED")).toBe(true);
  });
});
