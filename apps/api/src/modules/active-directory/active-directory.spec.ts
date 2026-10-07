import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { ActiveDirectoryService } from "./active-directory.service";

/**
 * Prompt 15 §100–§116 API discipline: domains are tenant-isolated;
 * credentials are reference names only (a secret-shaped value is
 * refused and never stored); scan starts are gated on a VERIFIED
 * target; offensive tool requests are refused AND audited
 * (AD_OFFENSIVE_ACTION_BLOCKED); raw graph access is OWNER/ADMIN and
 * audited per access (§30); attack paths are framed as models, never
 * executions (§35); compliance output never claims certification
 * (§81).
 */

const owner = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const analyst = { id: "u-4", email: "a@example.com", organizationId: "org-1", role: "ANALYST" as const };
const viewer = { id: "u-3", email: "v@example.com", organizationId: "org-1", role: "VIEWER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

interface State {
  targets: Array<Record<string, unknown>>;
  forests: Array<Record<string, unknown>>;
  domains: Array<Record<string, unknown>>;
  profiles: Array<Record<string, unknown>>;
  controllers: Array<Record<string, unknown>>;
  snapshots: Array<Record<string, unknown>>;
  users: Array<Record<string, unknown>>;
  groups: Array<Record<string, unknown>>;
  computers: Array<Record<string, unknown>>;
  trusts: Array<Record<string, unknown>>;
  gpos: Array<Record<string, unknown>>;
  relationships: Array<Record<string, unknown>>;
  attackPaths: Array<Record<string, unknown>>;
  shares: Array<Record<string, unknown>>;
  cas: Array<Record<string, unknown>>;
  templates: Array<Record<string, unknown>>;
  drift: Array<Record<string, unknown>>;
  artifacts: Array<Record<string, unknown>>;
  assessments: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  scopes: Array<Record<string, unknown>>;
  engagements: Array<Record<string, unknown>>;
  audits: Array<Record<string, unknown>>;
}

function freshState(): State {
  return {
    targets: [
      { id: "t-ad", workspaceId: "ws-1", name: "corp-ad", type: "ACTIVE_DIRECTORY_DOMAIN", value: "corp.example", verified: true, status: "VERIFIED" },
    ],
    forests: [
      { id: "fo-1", workspaceId: "ws-1", name: "corp-forest", rootDomain: "corp.example", functionalLevel: null, assessmentState: "REGISTERED", createdAt: new Date(0) },
    ],
    domains: [{
      id: "dom-1", workspaceId: "ws-1", targetId: "t-ad", forestId: "fo-1", credentialProfileId: "prof-1",
      dnsName: "corp.example", netbiosName: "CORP", domainSid: "S-1-5-21-1004336348-1177238915-682003330",
      functionalLevel: "2016", environment: "PRODUCTION", criticality: "HIGH", status: "REGISTERED",
      lastSeen: new Date(0), lastAssessmentAt: null, createdAt: new Date(0),
    }],
    profiles: [{
      id: "prof-1", workspaceId: "ws-1", name: "corp assessment identity", identityKind: "READ_ONLY_DOMAIN",
      credentialReference: "vault:prod/ad/assessment-account", status: "CONFIGURED",
    }],
    controllers: [{
      id: "dc-1", workspaceId: "ws-1", domainId: "dom-1", hostname: "DC01", dnsName: "DC01.CORP.EXAMPLE",
      ipAddresses: ["192.0.2.11"], osName: "Windows Server 2022", osVersion: null, services: {},
    }],
    snapshots: [],
    users: [{
      id: "du-1", workspaceId: "ws-1", domainId: "dom-1", objectId: "S-1-5-21-1004336348-1177238915-682003330-1105",
      samAccountName: "rudra", displayName: "Rudra (fixture admin)", userPrincipalName: "rudra@corp.example",
      enabled: true, privileged: true, privilegeEvidence: { via: ["DOMAIN ADMINS"] }, isServiceAccount: false,
      spnPresent: false, spns: [], passwordNeverExpires: false, passwordNotRequired: false,
      preauthNotRequired: false, delegationType: "NONE", riskScore: 62, riskFactors: [],
      lastLogonAt: null, passwordLastSetAt: null,
    }],
    groups: [{
      id: "dg-1", workspaceId: "ws-1", domainId: "dom-1", objectId: "S-1-5-21-1004336348-1177238915-682003330-512",
      name: "Domain Admins", groupScope: "GLOBAL", groupType: "SECURITY", privilegeClass: "PRIVILEGED", memberCount: 2,
    }],
    computers: [{
      id: "dcomp-1", workspaceId: "ws-1", domainId: "dom-1", objectId: "S-1-5-21-1004336348-1177238915-682003330-1001",
      hostname: "DC01", dnsName: "DC01.CORP.EXAMPLE", osName: "Windows Server 2022", osVersion: null,
      enabled: true, isDomainController: true, delegationType: "NONE", delegationTargets: [], riskScore: null, riskFactors: null,
    }],
    trusts: [{
      id: "dt-1", workspaceId: "ws-1", domainId: "dom-1", targetDomainName: "partner.example", direction: "OUTBOUND",
      trustType: "EXTERNAL", transitive: false, sidFilteringEnabled: false, selectiveAuthentication: false, lastSeen: new Date(0),
    }],
    gpos: [],
    relationships: [{
      id: "rel-1", workspaceId: "ws-1", domainId: "dom-1", fromType: "USER",
      fromRef: "S-1-5-21-1004336348-1177238915-682003330-1105", toType: "GROUP",
      toRef: "S-1-5-21-1004336348-1177238915-682003330-512", relationship: "MEMBER_OF",
      source: "bloodhound-connector", confidence: "HIGH", evidenceRef: null, lastSeen: new Date(0),
    }],
    attackPaths: [{
      id: "ap-1", workspaceId: "ws-1", domainId: "dom-1", scanId: "scan-1",
      title: "rudra → Domain Admins → DC01", steps: [], status: "EVIDENCE_BACKED", confidence: "HIGH",
      riskScore: 71, riskFactors: {}, createdAt: new Date(0),
    }],
    shares: [{
      id: "sh-1", workspaceId: "ws-1", domainId: "dom-1", host: "FILE01", shareName: "Public",
      accessLevel: "READ_WRITE", anonymousAccess: true, smbDialect: "SMB 1.0", signingRequired: false,
      source: "smbmap", lastSeen: new Date(0),
    }],
    cas: [{
      id: "ca-1", workspaceId: "ws-1", domainId: "dom-1", name: "CORP-CA", dnsName: "DC01.CORP.EXAMPLE",
      enrollmentServices: [], metadata: {},
    }],
    templates: [{
      id: "ct-1", workspaceId: "ws-1", domainId: "dom-1", caId: "ca-1", name: "VulnTemplate (fixture)",
      enabled: true, authenticationEkus: ["1.3.6.1.5.5.7.3.2"], managerApprovalRequired: false,
      authorizedSignaturesRequired: 0, riskClasses: ["ESC1"],
    }],
    drift: [{
      id: "dr-1", workspaceId: "ws-1", domainId: "dom-1", scanId: "scan-1", kind: "NEW_TRUST",
      objectRef: "partner.example", detail: "a new trust appeared — review signal, not classified malicious (§80)", detectedAt: new Date(0),
    }],
    artifacts: [],
    assessments: [{
      id: "ca-1", workspaceId: "ws-1", frameworkKey: "MS_AD_BASELINE", controlId: "MS-AD-4.1",
      subjectRef: "corp.example", status: "FAIL", evidence: "LDAP signing not required", assessedAt: new Date(0), scanId: "scan-1",
    }],
    findings: [], scopes: [], engagements: [], audits: [],
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
    activeDirectoryForest: model(state.forests, "fo"),
    activeDirectoryDomain: model(state.domains, "dom"),
    directoryCredentialProfile: model(state.profiles, "prof"),
    domainController: model(state.controllers, "dc"),
    directorySnapshot: model(state.snapshots, "snap"),
    directoryUser: model(state.users, "du"),
    directoryGroup: model(state.groups, "dg"),
    directoryComputer: model(state.computers, "dcomp"),
    directoryTrust: model(state.trusts, "dt"),
    groupPolicyObject: model(state.gpos, "gpo"),
    directoryRelationship: model(state.relationships, "rel"),
    adAttackPath: model(state.attackPaths, "ap"),
    smbShare: model(state.shares, "sh"),
    certificateAuthority: model(state.cas, "ca"),
    certificateTemplate: model(state.templates, "ct"),
    adDriftEvent: model(state.drift, "dr"),
    directoryArtifact: model(state.artifacts, "art"),
    controlAssessment: model(state.assessments, "asm"),
    finding: model(state.findings, "f"),
    scope: model(state.scopes, "scp"),
    assessment: model(state.engagements, "eng"),
  };
}

function makeService(state: State) {
  const prisma = fakePrisma(state);
  const audit = { record: async (e: Record<string, unknown>) => { state.audits.push(e); } };
  const orchestration = { startScan: async () => ({ scanId: "scan-1", status: "QUEUED" }) };
  return new ActiveDirectoryService(prisma as never, audit as never, orchestration as never);
}

describe("Prompt 15 API — domains", () => {
  it("registers a domain as target + forest + credential profile + DCs and audits it (§4/§7/§117)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const out = await svc.registerDomain(owner, {
      name: "branch-ad", dnsName: "branch.example", forestName: "corp-forest",
      credentialReference: "vault:prod/ad/branch-account", identityKind: "READ_ONLY_DOMAIN",
      environment: "PRODUCTION", criticality: "HIGH",
      domainControllers: [{ hostname: "BDC01", ipAddresses: ["192.0.2.21"] }],
    });
    expect(out.verified).toBe(false);
    expect(out.status).toBe("REGISTERED");
    const target = state.targets.find((t) => t.id === out.targetId)!;
    expect(target.type).toBe("ACTIVE_DIRECTORY_DOMAIN");
    const profile = state.profiles.find((p) => p.credentialReference === "vault:prod/ad/branch-account")!;
    expect(profile.identityKind).toBe("READ_ONLY_DOMAIN");
    // The profile holds the reference NAME only — no value field exists.
    expect(Object.keys(profile)).not.toContain("password");
    expect(state.controllers.some((c) => c.domainId === out.id && c.hostname === "BDC01")).toBe(true);
    expect(state.audits.some((a) => a.action === "AD_DOMAIN_REGISTERED")).toBe(true);
  });

  it("refuses a credential VALUE where a reference name belongs (§7)", async () => {
    const svc = makeService(freshState());
    await expect(svc.registerDomain(owner, {
      name: "bad", dnsName: "bad.example",
      credentialReference: "Tr0ub4dor&3-correct-horse-battery-staple",
    })).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.registerDomain(viewer, {
      name: "bad", dnsName: "bad.example",
    })).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("a domain without a credential reference registers as NOT_CONFIGURED (§9)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const out = await svc.registerDomain(owner, { name: "lab", dnsName: "lab.example" });
    expect(out.status).toBe("NOT_CONFIGURED");
    const validation = await svc.validateDomain(owner, out.id);
    expect(validation.status).toBe("NOT_CONFIGURED");
  });

  it("validates a well-formed reference (§9)", async () => {
    const svc = makeService(freshState());
    const out = await svc.validateDomain(owner, "dom-1");
    expect(out.status).toBe("VALIDATED");
  });

  it("scan start is gated on a VERIFIED target and audited (§3/§117)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const started = await svc.startDomainScan(owner, "dom-1", { profile: "AD_BASELINE" });
    expect(started.scanId).toBe("scan-1");
    expect(state.audits.some((a) => a.action === "AD_SCAN_STARTED")).toBe(true);

    const state2 = freshState();
    state2.targets[0]!.verified = false;
    const svc2 = makeService(state2);
    await expect(svc2.startDomainScan(owner, "dom-1", { profile: "AD_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("an offensive tool request is refused AND audited (§112/§117/§120)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.assertNoOffensiveTools(owner, "dom-1", ["netexec", "impacket"]))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(state.audits.some((a) => a.action === "AD_OFFENSIVE_ACTION_BLOCKED")).toBe(true);
    // Defensive tools pass the assertion silently.
    await expect(svc.assertNoOffensiveTools(owner, "dom-1", ["pingcastle", "certipy-posture"])).resolves.toBeUndefined();
  });
});

describe("Prompt 15 API — reads, RBAC, tenant isolation (§101/§116)", () => {
  it("lists identities for analysts but not viewers; users carry no credential material (§92)", async () => {
    const svc = makeService(freshState());
    const out = await svc.listUsers(analyst, {});
    expect(out.items).toHaveLength(1);
    expect(out.items[0]!.samAccountName).toBe("rudra");
    expect(JSON.stringify(out)).not.toMatch(/passwordHash|ntHash|credentialValue/i);
    await expect(svc.listUsers(viewer, {})).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("raw graph is OWNER/ADMIN only and audited per access (§30/§117)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.getRawGraph(analyst, {})).rejects.toBeInstanceOf(ForbiddenException);
    const out = await svc.getRawGraph(owner, { domainId: "dom-1" });
    expect(out.edges).toHaveLength(1);
    expect(state.audits.some((a) => a.action === "DIRECTORY_ARTIFACT_ACCESSED")).toBe(true);
  });

  it("attack paths are framed as models; ADCS exposes risk classes, no exploit action (§35/§49)", async () => {
    const svc = makeService(freshState());
    const paths = await svc.listAttackPaths(analyst, {});
    expect(paths.framing).toContain("never executed");
    expect(paths.items.every((p) => p.status !== "COMPROMISED")).toBe(true);
    const adcs = await svc.listAdcs(analyst, {});
    expect(adcs.templates[0]!.riskClasses).toContain("ESC1");
  });

  it("compliance output carries the no-certification disclaimer (§81)", async () => {
    const svc = makeService(freshState());
    const out = await svc.listCompliance(owner);
    expect(out.disclaimer).toContain("not a compliance certification");
    expect(out.byStatus.FAIL).toBe(1);
  });

  it("tenant isolation: a foreign workspace sees nothing (§116)", async () => {
    const svc = makeService(freshState());
    const domains = await svc.listDomains(foreign);
    expect(domains.items).toHaveLength(0);
    await expect(svc.getDomain(foreign, "dom-1")).rejects.toBeInstanceOf(NotFoundException);
    const users = await svc.listUsers({ ...foreign, role: "ANALYST" as const }, {});
    expect(users.items).toHaveLength(0);
  });
});
