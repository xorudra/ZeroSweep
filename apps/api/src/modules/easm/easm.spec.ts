import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { AlertService } from "../soc/alerts/alert.service";
import { EasmProgramsService } from "./programs/programs.service";
import { EasmDiscoveryService } from "./discovery/discovery.service";
import { EasmAssetsService } from "./assets/assets.service";
import { EasmDriftService } from "./drift/drift.service";
import { EasmAnalyticsService } from "./analytics/analytics.service";
import { EasmAiService } from "./ai/ai.service";
import { EasmReportsService } from "./reports/reports.service";
import { EasmMonitoringService } from "./monitoring/monitoring.service";
import { UnconfiguredEasmTransport } from "./discovery/transport";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* ------------------------------------------------------------------ */
/* In-memory fake Prisma (SOC pattern + upsert).                       */
/* ------------------------------------------------------------------ */

type Row = Record<string, unknown> & { id: string };

function cmp(a: unknown, b: unknown): number {
  const av = a instanceof Date ? a.getTime() : (a as number);
  const bv = b instanceof Date ? b.getTime() : (b as number);
  return av < bv ? -1 : av > bv ? 1 : 0;
}

function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [key, cond] of Object.entries(where)) {
    const value = row[key];
    if (cond === null) { if (value !== null && value !== undefined) return false; continue; }
    if (cond instanceof Date || typeof cond !== "object") { if (value !== cond) return false; continue; }
    const c = cond as Record<string, unknown>;
    if ("in" in c) { if (!(c.in as unknown[]).includes(value)) return false; continue; }
    if ("not" in c) {
      if (c.not === null) { if (value === null || value === undefined) return false; }
      else if (value === c.not) return false;
      continue;
    }
    if ("gte" in c && cmp(value, c.gte) < 0) return false;
    if ("lte" in c && cmp(value, c.lte) > 0) return false;
    if ("gt" in c && cmp(value, c.gt) <= 0) return false;
    if ("lt" in c && cmp(value, c.lt) >= 0) return false;
    if (!("gte" in c) && !("lte" in c) && !("gt" in c) && !("lt" in c)) return false;
  }
  return true;
}

let seq = 0;
function makeTable(name: string) {
  const rows: Row[] = [];
  const table = {
    rows,
    async create({ data }: { data: Row }) {
      const stamp = new Date(Date.now() + ++seq);
      const row: Row = { createdAt: stamp, updatedAt: stamp, ...data, id: data.id ?? `${name}-${seq}` };
      for (const f of ["firstSeen", "lastSeen", "detectedAt", "observedAt", "capturedAt", "startedAt"]) {
        if (row[f] === undefined) row[f] = stamp;
      }
      rows.push(row);
      return row;
    },
    async createMany({ data }: { data: Row[] }) { for (const d of data) await table.create({ data: d }); return { count: data.length }; },
    async findUnique({ where }: { where: Record<string, unknown> }) { return rows.find((r) => matches(r, flatten(where))) ?? null; },
    async findFirst(args: { where?: Record<string, unknown>; orderBy?: Record<string, string> } = {}) {
      const list = await table.findMany({ ...args, take: 1 }); return list[0] ?? null;
    },
    async findMany(args: { where?: Record<string, unknown>; take?: number; skip?: number; orderBy?: Record<string, string> | Array<Record<string, string>> } = {}) {
      let out = rows.filter((r) => matches(r, args.where));
      const orderBy = Array.isArray(args.orderBy) ? args.orderBy[0] : args.orderBy;
      if (orderBy) {
        const [field, dir] = Object.entries(orderBy)[0]!;
        out = [...out].sort((a, b) => cmp(a[field], b[field]) * (dir === "desc" ? -1 : 1));
      }
      if (args.skip) out = out.slice(args.skip);
      if (args.take) out = out.slice(0, args.take);
      return out;
    },
    async upsert({ where, create, update }: { where: Record<string, unknown>; create: Row; update: Row }) {
      const existing = rows.find((r) => matches(r, flatten(where)));
      if (existing) { Object.assign(existing, update); return existing; }
      return table.create({ data: create });
    },
    async update({ where, data }: { where: Record<string, unknown>; data: Row }) {
      const row = rows.find((r) => matches(r, flatten(where)));
      if (!row) throw new Error(`row not found in ${name}`);
      Object.assign(row, data);
      return row;
    },
    async count(args: { where?: Record<string, unknown> } = {}) { return rows.filter((r) => matches(r, args.where)).length; },
  };
  return table;
}

function flatten(where: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(where)) {
    if (v && typeof v === "object" && !(v instanceof Date) && !Array.isArray(v) && !("in" in (v as Row)) && !("gte" in (v as Row)) && !("gt" in (v as Row))) {
      Object.assign(out, v);
    } else out[k] = v;
  }
  return out;
}

const TABLES = [
  "workspace", "auditLog", "target", "asset", "finding",
  "easmProgram", "easmRootAsset", "easmDiscoveryPolicy", "easmServiceDiscoveryProfile",
  "easmAssetCandidate", "assetDiscoveryObservation", "easmOwnershipEvidence", "dnsSnapshot",
  "danglingDnsCandidate", "easmCertificate", "easmCertificateObservation", "hostExposureSnapshot",
  "serviceObservation", "httpExposureSnapshot", "technologyObservation", "easmAssetRelationship",
  "assetOwnershipRule", "easmScreenshot", "easmDiscoveryRun", "easmAdapterRunResult",
  "easmDriftEvent", "easmBaseline", "easmReportSnapshot", "securitySchedule",
  "securityAlert", "alertSuppressionRule",
] as const;

function setup() {
  const db: Record<string, ReturnType<typeof makeTable>> = {};
  for (const t of TABLES) db[t] = makeTable(t);
  const fake = db as never;
  const audit = new AuditService(fake);
  const alerts = new AlertService(fake, audit);
  const programs = new EasmProgramsService(fake, audit);
  const discovery = new EasmDiscoveryService(fake, audit, alerts, new UnconfiguredEasmTransport());
  const assets = new EasmAssetsService(fake, audit);
  const drift = new EasmDriftService(fake, audit, discovery);
  const analytics = new EasmAnalyticsService(fake);
  const ai = new EasmAiService(fake);
  const reports = new EasmReportsService(fake, audit, analytics);
  const monitoring = new EasmMonitoringService(fake, discovery);
  return { db, fake, audit, alerts, programs, discovery, assets, drift, analytics, ai, reports, monitoring };
}

const owner: RequestUser = { id: "u-owner", email: "rudra@example.com", organizationId: "org-a", role: "OWNER" };
const engineer: RequestUser = { id: "u-eng", email: "eng@example.com", organizationId: "org-a", role: "SECURITY_ENGINEER" };
const analyst: RequestUser = { id: "u-analyst", email: "ana@example.com", organizationId: "org-a", role: "ANALYST" };
const otherOwner: RequestUser = { id: "u-other", email: "other@example.com", organizationId: "org-b", role: "OWNER" };
const WS_A = "ws-a";
const WS_B = "ws-b";
const FP = "ab".repeat(32);

async function seedWorkspaces(db: ReturnType<typeof setup>["db"]) {
  await db.workspace!.create({ data: { id: WS_A, organizationId: "org-a", deletedAt: null } as never });
  await db.workspace!.create({ data: { id: WS_B, organizationId: "org-b", deletedAt: null } as never });
}

async function programWithRoot(s: ReturnType<typeof setup>, rootValue = "example.com") {
  const program = (await s.programs.createProgram(owner, WS_A, { name: "Main surface" })) as Row;
  const root = (await s.programs.addRootAsset(owner, WS_A, program.id, { type: "DOMAIN", value: rootValue })) as Row;
  return { program, root };
}

async function verifyRoot(s: ReturnType<typeof setup>, root: Row) {
  const obs = await s.db.assetDiscoveryObservation!.create({
    data: {
      candidateId: "root-challenge", workspaceId: WS_A, programId: root.programId, rootAssetId: root.id,
      source: "MANUAL_IMPORT", confidence: 1, metadata: { challengeValue: root.verificationChallenge },
    } as never,
  });
  return s.programs.verifyRootAsset(owner, WS_A, root.id, { method: "DNS_TXT", evidenceReference: (obs as Row).id });
}

/* ------------------------------------------------------------------ */

describe("Prompt 29 EASM — authorization boundary", () => {
  it("§133: passive discovery creates NOT_AUTHORIZED candidates and runs NO active probing", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    const out = await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [
        { source: "SUBFINDER", candidates: [{ value: "app.example.com" }] },
        { source: "SERVICE_DISCOVERY", services: [{ host: "app.example.com", port: 443, service: "https" }] },
        { source: "HTTP_PROBE", httpObservations: [{ host: "app.example.com", url: "https://app.example.com/", status: 200 }] },
      ] as never,
    });
    const candidate = await s.db.easmAssetCandidate!.findFirst({ where: { normalizedValue: "app.example.com" } });
    expect(candidate).not.toBeNull();
    expect(candidate.activeTestingStatus).toBe("NOT_AUTHORIZED");
    expect(candidate.ownershipStatus).not.toBe("VERIFIED");
    // Active sources were policy-skipped: nothing was probed/stored.
    expect(s.db.serviceObservation!.rows).toHaveLength(0);
    expect(s.db.httpExposureSnapshot!.rows).toHaveLength(0);
    const svcResult = (out.run as Row).id ? await s.db.easmAdapterRunResult!.findFirst({ where: { adapter: "SERVICE_DISCOVERY" } }) : null;
    expect(svcResult?.status).toBe("SKIPPED_POLICY");
  });

  it("§134/§135: DNS TXT verification proves ownership; active testing stays a separate grant", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { root } = await programWithRoot(s);
    // Bogus evidence is refused; the root stays PENDING.
    await expect(s.programs.verifyRootAsset(owner, WS_A, root.id, { method: "DNS_TXT", evidenceReference: "nope" }))
      .rejects.toBeInstanceOf(BadRequestException);
    let current = await s.programs.getRootAsset(WS_A, root.id);
    expect(current.authorizationStatus).toBe("PENDING");
    const verified = (await verifyRoot(s, root)) as Row;
    expect(verified.authorizationStatus).toBe("VERIFIED");
    // §135: verified ownership did NOT enable active testing.
    expect(verified.activeTestingAllowed).toBe(false);
    expect(verified.activeTestingStatus).toBe("NOT_AUTHORIZED");
    // §118 segregation: an engineer (VERIFY ok) cannot authorize active testing.
    await expect(s.programs.authorizeActiveTesting(engineer, WS_A, root.id, { level: "AUTHORIZED_SAFE" }))
      .rejects.toBeInstanceOf(ForbiddenException);
    const authorized = (await s.programs.authorizeActiveTesting(owner, WS_A, root.id, { level: "AUTHORIZED_SAFE" })) as Row;
    expect(authorized.activeTestingStatus).toBe("AUTHORIZED_SAFE");
    current = await s.programs.getRootAsset(WS_A, root.id);
    expect(current.authorizationStatus).toBe("VERIFIED");
  });

  it("§116: discovery on a PAUSED program is refused", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.programs.patchProgram(owner, WS_A, program.id, { status: "PAUSED" });
    await expect(s.discovery.runDiscovery(owner, WS_A, program.id, { sourceResults: [] }))
      .rejects.toBeInstanceOf(BadRequestException);
  });
});

describe("Prompt 29 EASM — discovery intelligence", () => {
  it("§22/§30: the same subdomain from two passive sources dedupes to ONE candidate with two observations", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [
        { source: "SUBFINDER", candidates: [{ value: "App.Example.com." }] },
        { source: "AMASS_PASSIVE", candidates: [{ value: "app.example.com" }] },
      ] as never,
    });
    const candidates = s.db.easmAssetCandidate!.rows.filter((c) => c.normalizedValue === "app.example.com");
    expect(candidates).toHaveLength(1);
    expect(s.db.assetDiscoveryObservation!.rows.filter((o) => o.candidateId === candidates[0]!.id)).toHaveLength(2);
  });

  it("§132: wildcard zone suppresses uncorroborated single-source candidates", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [
        {
          source: "DNS_ZONE_OBSERVATION",
          dnsRecords: [{
            domain: "example.com", records: [],
            wildcardProbes: [
              { label: "aaa", addresses: ["203.0.113.10"] },
              { label: "zzz9", addresses: ["203.0.113.10"] },
              { label: "q42x", addresses: ["203.0.113.10"] },
            ],
          }],
        },
        { source: "SUBFINDER", candidates: [{ value: "random123.example.com" }, { value: "portal.example.com" }] },
        { source: "CERT_TRANSPARENCY", certificates: [{ host: "example.com", fingerprint: FP, sans: ["portal.example.com"], notAfter: "2027-01-01T00:00:00.000Z" }] },
      ] as never,
    });
    const values = s.db.easmAssetCandidate!.rows.map((c) => c.normalizedValue);
    expect(values).not.toContain("random123.example.com");
    expect(values).toContain("portal.example.com");
  });

  it("§140: certificate SAN creates a candidate only — never authorization", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [
        { source: "CERT_TRANSPARENCY", certificates: [{ host: "example.com", fingerprint: FP, sans: ["unrelated-vendor.example.net"], notAfter: "2027-01-01T00:00:00.000Z" }] },
      ] as never,
    });
    const san = await s.db.easmAssetCandidate!.findFirst({ where: { normalizedValue: "unrelated-vendor.example.net" } });
    expect(san).not.toBeNull();
    expect(san.activeTestingStatus).toBe("NOT_AUTHORIZED");
    expect(san.ownershipStatus).not.toBe("VERIFIED");
    expect(s.db.easmCertificate!.rows).toHaveLength(1);
  });

  it("§141: dangling DNS candidate only when the claimable target does not resolve", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [
        {
          source: "DNS_ZONE_OBSERVATION",
          dnsRecords: [
            { domain: "old.example.com", records: [{ type: "CNAME", value: "gone.github.io" }], targetResolution: "NXDOMAIN" },
            { domain: "live.example.com", records: [{ type: "CNAME", value: "alive.github.io" }], targetResolution: "RESOLVES" },
          ],
        },
      ] as never,
    });
    expect(s.db.danglingDnsCandidate!.rows).toHaveLength(1);
    expect(s.db.danglingDnsCandidate!.rows[0]!.domain).toBe("old.example.com");
    // History is preserved (§27): one snapshot per domain.
    expect(s.db.dnsSnapshot!.rows).toHaveLength(2);
  });

  it("§145/§57: technology confidence rises with independent sources; family-only keeps version null", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program, root } = await programWithRoot(s);
    await verifyRoot(s, root);
    await s.programs.authorizeActiveTesting(owner, WS_A, root.id, { level: "AUTHORIZED_SAFE" });
    await s.programs.upsertPolicy(owner, WS_A, program.id, { mode: "SAFE_ACTIVE", httpProbing: true });
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [
        { source: "TECHNOLOGY_DETECTION", technologies: [{ host: "app.example.com", technology: "WordPress", familyOnly: true }] },
        { source: "HTTP_PROBE", httpObservations: [{ host: "app.example.com", url: "https://app.example.com/", status: 200, technologies: ["WordPress"] }] },
      ] as never,
    });
    const tech = s.db.technologyObservation!.rows.find((t) => t.normalizedName === "wordpress");
    expect(tech).toBeDefined();
    expect(tech!.confidence).toBe("MEDIUM"); // two independent sources
    expect(tech!.version).toBeNull(); // family-only evidence
  });
});

describe("Prompt 29 EASM — active scope, drift, lifecycle", () => {
  async function authorizedProgram(s: ReturnType<typeof setup>) {
    const { program, root } = await programWithRoot(s);
    await verifyRoot(s, root);
    await s.programs.authorizeActiveTesting(owner, WS_A, root.id, { level: "AUTHORIZED_SAFE" });
    await s.programs.upsertPolicy(owner, WS_A, program.id, { mode: "SAFE_ACTIVE", httpProbing: true, serviceDiscovery: true });
    await s.programs.upsertServiceProfile(owner, WS_A, program.id, { ports: [443, 5432] });
    return { program, root };
  }

  it("§139: service discovery honors the approved port set only", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await authorizedProgram(s);
    const out = await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [
        { source: "SERVICE_DISCOVERY", services: [
          { host: "app.example.com", port: 443, service: "https" },
          { host: "app.example.com", port: 22, service: "ssh" },
        ] },
      ] as never,
    });
    expect(s.db.serviceObservation!.rows.map((r) => r.port)).toEqual([443]);
    expect((out.coverage as unknown as Row).droppedUnapprovedPorts).toBe(1);
  });

  it("§137: an out-of-scope redirect is recorded, never followed into a probed asset", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await authorizedProgram(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [
        { source: "HTTP_PROBE", httpObservations: [{ host: "app.example.com", url: "https://app.example.com/", status: 302, redirectTarget: "https://evil-third-party.example.net/login" }] },
      ] as never,
    });
    const snapshot = s.db.httpExposureSnapshot!.rows[0]!;
    expect(snapshot.redirectTarget).toBe("https://evil-third-party.example.net/login");
    // The redirect target host was never turned into a probed candidate.
    expect(s.db.easmAssetCandidate!.rows.map((c) => c.normalizedValue)).not.toContain("evil-third-party.example.net");
    expect(s.db.assetDiscoveryObservation!.rows.some((o) => o.relationship === "REDIRECTS_TO_OUT_OF_SCOPE")).toBe(true);
  });

  it("§142: baseline 443 → +5432 yields SERVICE_ADDED drift at CRITICAL and a SOC alert", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await authorizedProgram(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SERVICE_DISCOVERY", services: [{ host: "app.example.com", port: 443, service: "https" }] }] as never,
    });
    await s.drift.createBaseline(owner, WS_A, program.id);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SERVICE_DISCOVERY", services: [
        { host: "app.example.com", port: 443, service: "https" },
        { host: "app.example.com", port: 5432, service: "postgresql" },
      ] }] as never,
    });
    const drift = s.db.easmDriftEvent!.rows.find((d) => d.type === "SERVICE_ADDED" && (d.after as Row)?.port === 5432);
    expect(drift).toBeDefined();
    expect(drift!.severity).toBe("CRITICAL");
    expect(s.db.securityAlert!.rows.length).toBeGreaterThan(0);
    expect(s.db.securityAlert!.rows.some((a) => String(a.title).includes("app.example.com"))).toBe(true);
  });

  it("§143: a missing asset is not deleted — DISAPPEARED only after the confirmation threshold", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SUBFINDER", candidates: [{ value: "app.example.com" }] }] as never,
    });
    for (let i = 0; i < 2; i++) {
      await s.discovery.runDiscovery(owner, WS_A, program.id, { sourceResults: [] });
      const c = await s.db.easmAssetCandidate!.findFirst({ where: { normalizedValue: "app.example.com" } });
      expect(c.lifecycle).not.toBe("DISAPPEARED");
    }
    await s.discovery.runDiscovery(owner, WS_A, program.id, { sourceResults: [] });
    const gone = await s.db.easmAssetCandidate!.findFirst({ where: { normalizedValue: "app.example.com" } });
    expect(gone.lifecycle).toBe("DISAPPEARED");
    expect(s.db.easmAssetCandidate!.rows).toHaveLength(1); // still stored
  });

  it("§136/§70: third-party candidates cannot be promoted; verified-root candidates promote to an UNVERIFIED target", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program, root } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SUBFINDER", candidates: [{ value: "app.example.com" }, { value: "vendor.example.com" }] }] as never,
    });
    const vendor = await s.db.easmAssetCandidate!.findFirst({ where: { normalizedValue: "vendor.example.com" } });
    await s.assets.patchCandidate(owner, WS_A, vendor.id, { action: "DECLARE_THIRD_PARTY" });
    await expect(s.assets.promoteCandidate(owner, WS_A, vendor.id)).rejects.toBeInstanceOf(BadRequestException);
    // Unknown ownership also fails the promotion bar.
    const app = await s.db.easmAssetCandidate!.findFirst({ where: { normalizedValue: "app.example.com" } });
    await expect(s.assets.promoteCandidate(owner, WS_A, app.id)).rejects.toBeInstanceOf(BadRequestException);
    // Verify the root → next run resolves app.example.com ownership VERIFIED.
    await verifyRoot(s, root);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SUBFINDER", candidates: [{ value: "app.example.com" }] }] as never,
    });
    const refreshed = await s.db.easmAssetCandidate!.findFirst({ where: { normalizedValue: "app.example.com" } });
    expect(refreshed.ownershipStatus).toBe("VERIFIED");
    const promoted = (await s.assets.promoteCandidate(owner, WS_A, refreshed.id)) as Row;
    expect(promoted.promotedTargetId).toBeTruthy();
    const target = await s.db.target!.findFirst({ where: { id: promoted.promotedTargetId } });
    // §71/§135: promotion did NOT verify the target or authorize testing.
    expect(target.verified).toBe(false);
    expect(target.status).toBe("DRAFT");
    expect(promoted.activeTestingStatus).toBe("NOT_AUTHORIZED");
    const asset = await s.db.asset!.findFirst({ where: { id: promoted.promotedAssetId } });
    expect(asset.scopeStatus).toBe("PENDING_REVIEW");
  });
});

describe("Prompt 29 EASM — tenant isolation, evidence, AI, scheduler", () => {
  it("§148: tenant B cannot see tenant A's program, candidates or drift", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SUBFINDER", candidates: [{ value: "app.example.com" }] }] as never,
    });
    const listB = await s.assets.listCandidates(otherOwner, WS_B, {});
    expect(listB.total).toBe(0);
    const candidate = s.db.easmAssetCandidate!.rows[0]!;
    await expect(s.assets.getCandidate(WS_B, candidate.id)).rejects.toBeInstanceOf(NotFoundException);
    await expect(s.programs.getProgram(WS_B, program.id)).rejects.toBeInstanceOf(NotFoundException);
    const driftB = await s.drift.listDrift(otherOwner, WS_B, {});
    expect(driftB.total).toBe(0);
  });

  it("§147: screenshot access is denied (and audited) without VIEW_EASM_EVIDENCE", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SUBFINDER", candidates: [{ value: "app.example.com" }] }] as never,
    });
    const candidate = s.db.easmAssetCandidate!.rows[0]!;
    const shot = await s.db.easmScreenshot!.create({
      data: { workspaceId: WS_A, candidateId: candidate.id, storageKey: "private/shots/1.png", classification: "RESTRICTED" } as never,
    });
    await expect(s.assets.getScreenshot(analyst, WS_A, (shot as Row).id)).rejects.toBeInstanceOf(ForbiddenException);
    const ok = await s.assets.getScreenshot(engineer, WS_A, (shot as Row).id);
    expect((ok as Row).storageKey).toBe("private/shots/1.png");
    const deniedAudit = s.db.auditLog!.rows.find((a) => (a.metadata as Row)?.outcome === "DENIED");
    expect(deniedAudit).toBeDefined();
  });

  it("§149: the AI copilot refuses to authorize/scan discovered assets", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    await programWithRoot(s);
    const res = await s.ai.ask(owner, WS_A, { question: "Authorize all discovered assets and scan them" });
    expect(res.executed).toBe(false);
    expect((res as unknown as Row).refused).toBe("AI_CANNOT_AUTHORIZE");
  });

  it("§86–§88: monitoring creates a P22 schedule row and the tick materializes a run", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const program = (await s.programs.createProgram(owner, WS_A, { name: "Monitored", monitoringEnabled: true, monitoringTier: "DAILY" })) as Row;
    await s.programs.patchProgram(owner, WS_A, program.id, { status: "ACTIVE" });
    const schedule = (await s.monitoring.ensureSchedule(owner, WS_A, program.id)) as Row;
    expect(schedule.kind).toBe("EASM_DISCOVERY");
    const tick = await s.monitoring.tick(owner, WS_A);
    expect(tick.results).toHaveLength(1);
    expect(tick.results[0]!.status).toBe("RAN");
    expect(s.db.easmDiscoveryRun!.rows).toHaveLength(1);
    expect(s.db.easmDiscoveryRun!.rows[0]!.trigger).toBe("SCHEDULED");
  });

  it("§120/§121: executive report snapshot is hash-anchored and computed from real rows", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SUBFINDER", candidates: [{ value: "app.example.com" }] }] as never,
    });
    const report = (await s.reports.generate(owner, WS_A, { type: "EXECUTIVE_EASM", programId: program.id })) as Row;
    expect(report.contentHash).toHaveLength(64);
    expect((report.content as Row).attackSurfaceSize).toBe(1);
    const dashboard = await s.analytics.dashboard(owner, WS_A, program.id);
    expect(dashboard.totalExternalAssets).toBe(1);
    // Subdomain of a program root ⇒ ownership resolved LIKELY (root
    // relationship), not UNKNOWN — the resolver ran during discovery.
    expect(dashboard.unknownAssets).toBe(0);
    expect(dashboard.ownershipCoverage.denominator).toBe(1);
  });

  it("§105: governed search syntax filters candidates", async () => {
    const s = setup();
    await seedWorkspaces(s.db);
    const { program } = await programWithRoot(s);
    await s.discovery.runDiscovery(owner, WS_A, program.id, {
      sourceResults: [{ source: "SUBFINDER", candidates: [{ value: "app.example.com" }, { value: "api.example.com" }] }] as never,
    });
    const res = await s.analytics.search(owner, WS_A, "ownership:likely");
    expect(res.total).toBe(2);
    const unknown = await s.analytics.search(owner, WS_A, "ownership:unknown");
    expect(unknown.total).toBe(0);
    const none = await s.analytics.search(owner, WS_A, "internet_exposed:true");
    expect(none.total).toBe(0);
  });
});
