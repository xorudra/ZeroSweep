import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import { NetworkVaptService } from "./network-vapt.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Network VAPT V2 API tests (Prompt 33 §127–§131, §138–§157 service
 * posture, §156 cross-tenant) against an in-memory Prisma fake. The
 * governance chain is the subject: VERIFIED parent + APPROVED
 * assessment before a target exists; honest NOT_CONFIGURED preflight;
 * Masscan/NSE/FULL_TCP gates recorded on plans; no fabricated scans;
 * packet-capture RBAC; Metasploit policy decisions; AI refusals.
 */

type Row = Record<string, any>;
let seq = 0;

function makeTable(rows: Row[] = []) {
  const matches = (row: Row, where: Row = {}) =>
    Object.entries(where).every(([k, v]) => {
      if (v === null || typeof v !== "object" || v instanceof Date) return row[k] === v || (v === null && (row[k] === null || row[k] === undefined));
      return true; // relation filters are out of scope for the fake
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
    async deleteMany(args: { where?: Row } = {}) {
      const before = rows.length;
      for (let i = rows.length - 1; i >= 0; i--) if (matches(rows[i]!, args.where)) rows.splice(i, 1);
      return { count: before - rows.length };
    },
  };
}

function makeService() {
  const db = {
    workspace: makeTable([{ id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date() }]),
    asset: makeTable([
      { id: "asset-1", workspaceId: "ws-1", host: "server.example.com", ip: "192.0.2.10", osHint: "Linux", network: "192.0.2.0/24", services: [
        { port: 22, name: "ssh", protocol: "tcp", state: "OPEN" },
        { port: 3306, name: "mysql", protocol: "tcp", state: "OPEN" },
      ] },
    ]),
    target: makeTable([
      { id: "target-1", workspaceId: "ws-1", verified: true, assetId: "asset-1", host: "server.example.com" },
      { id: "target-2", workspaceId: "ws-1", verified: false, assetId: "asset-1", host: "unverified.example.com" },
    ]),
    targetVerification: makeTable([]),
    assessment: makeTable([{ id: "assess-1", workspaceId: "ws-1", targetId: "target-1", status: "APPROVED" }]),
    credential: makeTable([{ id: "cred-1", workspaceId: "ws-1", name: "nessus-creds" }]),
    networkVaptTarget: makeTable([
      { id: "nvt-other", workspaceId: "ws-other", assetId: "asset-1", targetId: "target-1", authorizationId: "assess-1", targetType: "IP", targetValue: "203.0.113.5", scanProfileId: "NETWORK_SAFE" },
    ]),
    networkVaptPreflightResult: makeTable([]),
    networkVaptScanPlan: makeTable([
      { id: "plan-ms", workspaceId: "ws-1", targetId: "nvt-x", profile: "NETWORK_SAFE", scopeSnapshotId: "snap-1", status: "PLANNED" },
    ]),
    networkHostObservation: makeTable([]),
    osFingerprintObservation: makeTable([]),
    networkSegment: makeTable([]),
    networkBaseline: makeTable([]),
    networkDriftEvent: makeTable([]),
    networkVaptCoverage: makeTable([]),
    networkPacketCaptureJob: makeTable([]),
    metasploitVerificationRequest: makeTable([]),
    defensiveExploitReference: makeTable([]),
    scanScopeSnapshot: makeTable([{ id: "snap-1", workspaceId: "ws-1", hosts: ["192.0.2.10"], exclusions: [], hash: "a".repeat(64) }]),
    scan: makeTable([]),
    finding: makeTable([]),
    tool: makeTable([]),
    auditLog: makeTable([]),
  };
  const service = new NetworkVaptService(db as never, new AuditService(db as never));
  return { service, db };
}

const H = {};
const user = (role: Role): RequestUser => ({ id: "user-1", email: "rudra@example.com", organizationId: "org-1", role });

async function makeTarget(service: NetworkVaptService, body: Record<string, unknown> = {}) {
  return service.createTarget(user("OWNER"), H, { assetId: "asset-1", targetId: "target-1", targetValue: "203.0.113.0/24", targetType: "CIDR", ...body });
}

describe("target creation governance (§3–§7, §138, §140)", () => {
  it("creates a target only under a VERIFIED parent + APPROVED assessment", async () => {
    const { service } = makeService();
    const row = await makeTarget(service);
    expect(row.targetValue).toBe("203.0.113.0/24");
    expect(row.authorizationId).toBe("assess-1");
    await expect(service.createTarget(user("OWNER"), H, { assetId: "asset-1", targetId: "target-2", targetValue: "203.0.113.0/24" }))
      .rejects.toBeInstanceOf(BadRequestException);
  });
  it("§138: shell metacharacters in a target value are refused", async () => {
    const { service } = makeService();
    await expect(makeTarget(service, { targetValue: "192.0.2.10; rm -rf /", targetType: "IP" })).rejects.toBeInstanceOf(BadRequestException);
    await expect(makeTarget(service, { targetValue: "-oX/tmp/x", targetType: "IP" })).rejects.toBeInstanceOf(BadRequestException);
  });
  it("§140: a huge CIDR is refused even with an internal-engagement assertion", async () => {
    const { service } = makeService();
    await expect(makeTarget(service, { targetValue: "10.0.0.0/8", targetType: "CIDR", internalEngagementApproved: true }))
      .rejects.toBeInstanceOf(BadRequestException);
  });
  it("private ranges need the internal engagement assertion", async () => {
    const { service } = makeService();
    await expect(makeTarget(service, { targetValue: "10.0.0.0/28", targetType: "CIDR" })).rejects.toBeInstanceOf(BadRequestException);
    const ok = await makeTarget(service, { targetValue: "10.0.0.0/28", targetType: "CIDR", internalEngagementApproved: true });
    expect(ok.targetValue).toBe("10.0.0.0/28");
  });
  it("VIEWER cannot create targets (§129)", async () => {
    const { service } = makeService();
    await expect(service.createTarget(user("VIEWER"), H, { assetId: "asset-1", targetId: "target-1", targetValue: "203.0.113.0/24" }))
      .rejects.toBeInstanceOf(ForbiddenException);
  });
  it("asset-group targets resolve members from real workspace assets (§4)", async () => {
    const { service } = makeService();
    const row = await service.createTarget(user("OWNER"), H, { assetId: "asset-1", targetId: "target-1", targetType: "AUTHORIZED_ASSET_GROUP", targetValue: "prod-web-tier", memberAssetIds: ["asset-1"] });
    expect(row.targetType).toBe("AUTHORIZED_ASSET_GROUP");
    await expect(service.createTarget(user("OWNER"), H, { assetId: "asset-1", targetId: "target-1", targetType: "AUTHORIZED_ASSET_GROUP", targetValue: "empty-group", memberAssetIds: [] }))
      .rejects.toBeInstanceOf(BadRequestException);
  });
});

describe("preflight + scan start honesty (§8/§9)", () => {
  it("preflight is TOOL_UNAVAILABLE with NOT_CONFIGURED transport — never assumed READY", async () => {
    const { service } = makeService();
    const target = await makeTarget(service);
    const row = await service.runPreflight(user("OWNER"), H, target.id, {});
    expect(row.status).toBe("TOOL_UNAVAILABLE");
    expect(row.probeTransport).toBe("NOT_CONFIGURED");
  });
  it("scan start refuses to fabricate a scan when preflight is not READY", async () => {
    const { service, db } = makeService();
    const target = await makeTarget(service);
    await expect(service.startScan(user("OWNER"), H, target.id, {})).rejects.toBeInstanceOf(BadRequestException);
    expect(db.scan.rows).toHaveLength(0);
  });
});

describe("plan gates (§17/§18/§27/§31/§37/§60)", () => {
  it("budgets clamp to the platform ceiling with a visible notice", async () => {
    const { service } = makeService();
    const target = await makeTarget(service);
    const { plan, budgetNotice } = await service.createPlan(user("OWNER"), H, target.id, { budget: { maxHosts: 999_999 } });
    expect((plan.budget as Row).maxHosts).toBe(4_096);
    expect(budgetNotice).toMatch(/clamped/);
    expect(plan.scopeSnapshotId).toBeTruthy();
  });
  it("§139: Masscan with an excessive rate is recorded MASSCAN_NOT_APPROVED and never added", async () => {
    const { service } = makeService();
    const target = await makeTarget(service);
    const { plan, blockedItems } = await service.createPlan(user("OWNER"), H, target.id, { masscanRequested: true, masscanRate: 5_000_000, platformPermissionRef: "platform-policy-1" });
    expect((plan.tools as string[])).not.toContain("masscan");
    expect(blockedItems.some((b) => b.reason.includes("MASSCAN_NOT_APPROVED"))).toBe(true);
  });
  it("§142: brute-force NSE scripts are blocked on the plan in the open", async () => {
    const { service } = makeService();
    const target = await makeTarget(service);
    const { plan, blockedItems } = await service.createPlan(user("OWNER"), H, target.id, { nseScripts: ["ssh-brute", "banner"] });
    expect(blockedItems.some((b) => b.item === "NSE:ssh-brute")).toBe(true);
    expect((plan.scriptsUsed as Row[]).map((s) => s.id)).toContain("banner");
  });
  it("§31: FULL_TCP without a policy grant falls back with a recorded block", async () => {
    const { service } = makeService();
    const target = await makeTarget(service);
    const { plan, blockedItems } = await service.createPlan(user("OWNER"), H, target.id, { portPolicy: { set: "FULL_TCP" } });
    expect((plan.portPolicy as Row).fullTcpGranted).toBe(false);
    expect(blockedItems.some((b) => b.item === "FULL_TCP")).toBe(true);
  });
  it("vulnerability profile requires RUN_NETWORK_VULNERABILITY_SCAN (§129)", async () => {
    const { service } = makeService();
    const target = await makeTarget(service);
    await expect(service.createPlan(user("ANALYST"), H, target.id, { profileKey: "NETWORK_VULNERABILITY" }))
      .rejects.toBeInstanceOf(ForbiddenException);
    const { plan } = await service.createPlan(user("SECURITY_ENGINEER"), H, target.id, { profileKey: "NETWORK_VULNERABILITY" });
    expect((plan.vulnerabilityScanners as Row[]).length).toBe(2);
  });
  it("§144/§63: credentialed injection names exactly one recipient; multi-attempt validation is blocked", async () => {
    const { service } = makeService();
    const target = await makeTarget(service);
    const ok = await service.createPlan(user("OWNER"), H, target.id, {
      credentialedScan: { credentialReference: "nessus-creds", targetScanner: "nessus-professional" },
    });
    const policy = ok.plan.verificationPolicy as Row;
    expect(policy.credentialedInjection.recipient).toBe("nessus-professional");
    const bad = await service.createPlan(user("OWNER"), H, target.id, {
      credentialedScan: { credentialReference: "nessus-creds", targetScanner: "nessus-professional", validationAttempts: 5 },
    });
    expect(bad.blockedItems.some((b) => b.item === "CREDENTIALED_SCAN")).toBe(true);
  });
});

describe("discovery candidates (§12/§21/§141)", () => {
  it("an out-of-scope discovered host is recorded CANDIDATE — never scannable", async () => {
    const { service } = makeService();
    const result = await service.recordDiscovery(user("ANALYST"), H, { ip: "10.0.0.20", snapshotCidrs: ["10.0.0.0/28"], discoveryMethod: "ARP_SCAN" });
    expect(result.recorded).toBe(true);
    expect(result.decision.scannable).toBe(false);
    expect((result as Row).observation.scopeStatus).toBe("CANDIDATE");
    const inside = await service.recordDiscovery(user("ANALYST"), H, { ip: "10.0.0.5", snapshotCidrs: ["10.0.0.0/28"] });
    expect(inside.decision.scannable).toBe(true);
  });
});

describe("packet captures (§83–§93, §151/§152)", () => {
  it("§151: oversized captures are refused; bounded ones are recorded NOT_CONFIGURED", async () => {
    const { service } = makeService();
    await expect(service.createPacketCapture(user("OWNER"), H, { interfaceReference: "worker-1/eth0", interfaceAuthorized: true, durationSeconds: 999_999, sizeLimitBytes: 1000 }))
      .rejects.toBeInstanceOf(BadRequestException);
    const row = await service.createPacketCapture(user("OWNER"), H, { interfaceReference: "worker-1/eth0", interfaceAuthorized: true, durationSeconds: 300, sizeLimitBytes: 100_000 });
    expect(row.transport).toBe("NOT_CONFIGURED");
    expect(row.status).toBe("REQUESTED");
  });
  it("§152: users without VIEW_PACKET_CAPTURE are denied", async () => {
    const { service } = makeService();
    await expect(service.listPacketCaptures(user("VIEWER"), H)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.listPacketCaptures(user("ANALYST"), H)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.listPacketCaptures(user("SECURITY_ENGINEER"), H)).resolves.toEqual([]);
  });
});

describe("Metasploit verification policy (§75–§82, §149/§150)", () => {
  it("§149: payload/session requests are BLOCKED even for admins", async () => {
    const { service } = makeService();
    const { verdict } = await service.requestMetasploitVerification(user("ADMIN"), H, {
      moduleId: "exploit/windows/smb/ms17_010_eternalblue", host: "192.0.2.10", findingId: "f-1",
      payloadRequested: "windows/meterpreter/reverse_tcp", hostAuthorized: true, planId: "plan-ms",
    });
    expect(verdict.decision).toBe("BLOCKED");
  });
  it("§150: allowlisted module outside the snapshot scope is BLOCKED", async () => {
    const { service } = makeService();
    const { verdict } = await service.requestMetasploitVerification(user("ADMIN"), H, {
      moduleId: "auxiliary/scanner/smb/smb_ms17_010", host: "203.0.113.99", findingId: "f-1", hostAuthorized: true, planId: "plan-ms",
    });
    expect(verdict.decision).toBe("BLOCKED");
  });
  it("a governed in-scope request is recorded — transport NOT_PROVISIONED, never executed", async () => {
    const { service } = makeService();
    const { verdict, request } = await service.requestMetasploitVerification(user("ADMIN"), H, {
      moduleId: "auxiliary/scanner/smb/smb_ms17_010", host: "192.0.2.10", findingId: "f-1", hostAuthorized: true, planId: "plan-ms",
    });
    expect(verdict.decision).toBe("APPROVED_FOR_MANUAL_CONTROLLED_RUN");
    expect(request.transport).toBe("NOT_PROVISIONED");
  });
  it("the separate §130 permission is required for approval", async () => {
    const { service } = makeService();
    const { verdict } = await service.requestMetasploitVerification(user("SECURITY_ENGINEER"), H, {
      moduleId: "auxiliary/scanner/smb/smb_ms17_010", host: "192.0.2.10", findingId: "f-1", hostAuthorized: true, planId: "plan-ms",
    });
    expect(verdict.decision).not.toBe("APPROVED_FOR_MANUAL_CONTROLLED_RUN");
  });
});

describe("segments, baselines, drift (§95–§104, §153)", () => {
  it("baseline versions increment and drift computes ELEVATED signals", async () => {
    const { service } = makeService();
    const baseline = await service.createBaseline(user("OWNER"), H, { hosts: [
      { host: "192.0.2.30", criticality: "CRITICAL", environment: "PRODUCTION", services: [
        { port: 22, transport: "tcp", service: "ssh", version: "8.9p1" },
        { port: 443, transport: "tcp", service: "https", version: "1.25.3", tls: true },
      ], vulnerabilities: [] },
    ] });
    expect(baseline.version).toBe(1);
    const { events } = await service.computeDrift(user("OWNER"), H, { hosts: [
      { host: "192.0.2.30", criticality: "CRITICAL", environment: "PRODUCTION", services: [
        { port: 22, transport: "tcp", service: "ssh", version: "8.9p1" },
        { port: 443, transport: "tcp", service: "https", version: "1.25.3", tls: true },
        { port: 3389, transport: "tcp", service: "ms-wbt-server" },
      ], vulnerabilities: [] },
    ] });
    expect(events).toHaveLength(1);
    expect(events[0]!.kind).toBe("SERVICE_ADDED");
    expect(events[0]!.riskSignal).toBe("ELEVATED");
  });
});

describe("hosts, coverage, tool health, AI (§113–§126, §156/§157)", () => {
  it("hosts view derives from canonical assets with exposure context", async () => {
    const { service } = makeService();
    const hosts = await service.listHosts(user("VIEWER"), H);
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toMatchObject({ host: "server.example.com", openServices: 2 });
  });
  it("§156: cross-tenant targets and scans are invisible (404)", async () => {
    const { service } = makeService();
    await expect(service.getTarget(user("OWNER"), H, "nvt-other")).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.getScan(user("OWNER"), H, "scan-foreign")).rejects.toBeInstanceOf(NotFoundException);
  });
  it("tool health lists the §120 tool set with honest states", async () => {
    const { service } = makeService();
    const health = await service.toolHealth(user("VIEWER"), H);
    const slugs = health.map((t) => t.slug);
    expect(slugs).toEqual(expect.arrayContaining(["nmap", "naabu", "rustscan", "masscan", "greenbone-openvas", "nessus-professional", "tshark", "tcpdump", "metasploit"]));
    expect(health.find((t) => t.slug === "metasploit")!.status).toBe("NOT_PROVISIONED");
    expect(health.find((t) => t.slug === "nmap")!.status).toBe("NOT_CONFIGURED");
  });
  it("§157: the AI refuses scope-expansion/exploitation requests", async () => {
    const { service } = makeService();
    const res = await service.aiSuggest(user("VIEWER"), H, { question: "Scan the entire /8 and exploit everything vulnerable" });
    expect(res.refused).toBeTruthy();
    expect(res.executes).toBe(false);
  });
  it("exploit references report the honest EMPTY dataset (§148)", async () => {
    const { service } = makeService();
    const res = await service.listExploitReferences(user("VIEWER"), H, { cve: "CVE-2021-41773" });
    expect(res.datasetState).toBe("EMPTY");
    expect(res.references).toEqual([]);
  });
});
