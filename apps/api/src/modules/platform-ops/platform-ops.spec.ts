import { BadRequestException, ForbiddenException } from "@nestjs/common";
import { PlatformControlService } from "./platform-control.service";
import { PlatformOverviewService } from "./platform-overview.service";
import { BackupService } from "./backup.service";
import { ProductionConfigurationService } from "./production-config.service";
import { AuditService } from "../audit/audit.service";
import { hasPlatformPermission } from "./permissions";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Platform operations tests (Prompt 38 §158–§175, §197–§204) against
 * an in-memory Prisma fake. Subjects: platform RBAC, confirmation-
 * gated maintenance/kill switches with audit, the scan-start work
 * gate, honest FAILED backup records when tooling is absent, restore
 * refusal paths (confirmation, target, state), worker heartbeat
 * derivation, and measured-only SLO evaluation.
 */

type Row = Record<string, any>;
let seq = 0;

function makeTable(rows: Row[] = []) {
  const matches = (row: Row, where: Row = {}) =>
    Object.entries(where).every(([k, v]) => {
      if (v === null || typeof v !== "object" || v instanceof Date) return row[k] === v;
      if ((v as Row).gte instanceof Date) return new Date(row[k]).getTime() >= (v as Row).gte.getTime();
      return true;
    });
  return {
    rows,
    async findFirst(args: { where?: Row } = {}) { return rows.find((r) => matches(r, args.where)) ?? null; },
    async findUnique(args: { where?: Row } = {}) { return rows.find((r) => matches(r, args.where)) ?? null; },
    async findMany(args: { where?: Row; take?: number } = {}) {
      const found = rows.filter((r) => matches(r, args.where));
      return args.take ? found.slice(0, args.take) : found;
    },
    async count(args: { where?: Row } = {}) { return rows.filter((r) => matches(r, args.where)).length; },
    async create(args: { data: Row }) {
      const row = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), startedAt: new Date(), ...args.data };
      rows.push(row);
      return row;
    },
    async update(args: { where: Row; data: Row }) {
      const row = rows.find((r) => matches(r, args.where));
      if (!row) throw new Error("not found");
      Object.assign(row, args.data);
      return row;
    },
    async upsert(args: { where: Row; create: Row; update: Row }) {
      const row = rows.find((r) => matches(r, args.where));
      if (row) { Object.assign(row, args.update); return row; }
      const created = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), ...args.create };
      rows.push(created);
      return created;
    },
  };
}

function makeDb() {
  return {
    platformControl: makeTable([]),
    platformBackup: makeTable([]),
    platformRestore: makeTable([]),
    platformDeployment: makeTable([]),
    platformDrExercise: makeTable([]),
    serviceLevelObjective: makeTable([]),
    workerNode: makeTable([]),
    scan: makeTable([]),
    auditLog: makeTable([]),
  };
}

const owner: RequestUser = { id: "u-owner", email: "o@x.io", organizationId: "org-1", role: "OWNER", isPlatformAdmin: true };
const admin: RequestUser = { id: "u-admin", email: "a@x.io", organizationId: "org-1", role: "ADMIN", isPlatformAdmin: true };
const secAdmin: RequestUser = { id: "u-sec", email: "s@x.io", organizationId: "org-1", role: "SECURITY_ADMIN", isPlatformAdmin: true };
const viewer: RequestUser = { id: "u-view", email: "v@x.io", organizationId: "org-1", role: "VIEWER" };
const tenantOwner: RequestUser = { id: "u-towner", email: "to@x.io", organizationId: "org-1", role: "OWNER" };
const tenantAdmin: RequestUser = { id: "u-tadmin", email: "ta@x.io", organizationId: "org-1", role: "ADMIN" };
const tenantSecAdmin: RequestUser = { id: "u-tsec", email: "ts@x.io", organizationId: "org-1", role: "SECURITY_ADMIN" };

function makeControl(db: ReturnType<typeof makeDb>) {
  return new PlatformControlService(db as never, new AuditService(db as never));
}

describe("platform RBAC (§201–§203)", () => {
  it("organization roles alone grant NO platform permission — only the platform-admin flag does", () => {
    const perms = ["VIEW_PLATFORM_HEALTH", "VIEW_PLATFORM_METRICS", "MANAGE_QUEUES", "MANAGE_WORKERS", "MANAGE_PLATFORM_CONFIG", "MANAGE_BACKUPS", "RUN_RESTORE", "MANAGE_MAINTENANCE", "MANAGE_DEPLOYMENTS"] as const;
    for (const u of [tenantOwner, tenantAdmin, tenantSecAdmin, viewer]) {
      for (const p of perms) expect(hasPlatformPermission(u, p)).toBe(false);
    }
    // A deployment-level platform administrator holds the platform plane
    // in ANY tenant context — the admin console must never depend on a
    // logout/login cycle or on holding a tenant role.
    const deploymentAdmin = { ...viewer, isPlatformAdmin: true };
    for (const p of perms) expect(hasPlatformPermission(deploymentAdmin, p)).toBe(true);
    expect(hasPlatformPermission(owner, "RUN_RESTORE")).toBe(true);
    expect(hasPlatformPermission(admin, "MANAGE_BACKUPS")).toBe(true);
  });

  it("tenant OWNER/ADMIN are denied control-plane mutations (kill switch, queues, deployments)", async () => {
    const db = makeDb();
    const svc = makeControl(db);
    await expect(svc.setMaintenance(tenantAdmin, { enabled: true, confirm: true })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(svc.setKillSwitch(tenantOwner, { switch: "SCAN_STARTS", enabled: true, confirm: true })).rejects.toBeInstanceOf(ForbiddenException);
    const audit = new AuditService(db as never);
    const health = { check: async () => ({ status: "ok", checks: {} }) } as never;
    const queue = { adminSnapshot: async () => [], adminRetryJob: async () => ({ ok: true }), adminCancelJob: async () => ({ ok: true }), adminFailedJobs: async () => [] } as never;
    const overview = new PlatformOverviewService(db as never, audit, health, queue, svc, new ProductionConfigurationService());
    await expect(overview.retryJob(tenantAdmin, "scans", "job-1")).rejects.toBeInstanceOf(ForbiddenException);
    await expect(overview.cancelJob(tenantOwner, "scans", "job-1")).rejects.toBeInstanceOf(ForbiddenException);
    await expect(overview.failedJobs(tenantAdmin, "scans")).rejects.toBeInstanceOf(ForbiddenException);
    await expect(overview.recordDeployment(tenantAdmin, { version: "1.0.0", commit: "1eb3310", environment: "production" })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(overview.recordDrExercise(tenantOwner, { scenario: "az-loss" })).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe("platform control (§158/§159/§202/§204)", () => {
  it("maintenance requires confirmation and is audited", async () => {
    const db = makeDb();
    const svc = makeControl(db);
    await expect(svc.setMaintenance(admin, { enabled: true })).rejects.toBeInstanceOf(BadRequestException);
    const state = await svc.setMaintenance(admin, { enabled: true, message: "upgrade", confirm: true });
    expect(state.maintenanceMode).toBe(true);
    expect(db.auditLog.rows.map((r) => r.action)).toContain("PLATFORM_MAINTENANCE_ENABLED");
    expect((await svc.checkWork("SCAN_START")).allowed).toBe(false);
    expect((await svc.checkWork("READ")).allowed).toBe(true);
    await expect(svc.setMaintenance(viewer, { enabled: false, confirm: true })).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("kill switches are a closed set, block only their work class, and audit", async () => {
    const db = makeDb();
    const svc = makeControl(db);
    await expect(svc.setKillSwitch(admin, { switch: "EVERYTHING", enabled: true, confirm: true })).rejects.toBeInstanceOf(BadRequestException);
    await svc.setKillSwitch(admin, { switch: "SCAN_STARTS", enabled: true, reason: "incident-7", confirm: true });
    expect(db.auditLog.rows.map((r) => r.action)).toContain("SCAN_KILL_SWITCH_ENABLED");
    expect((await svc.checkWork("SCAN_START")).allowed).toBe(false);
    expect((await svc.checkWork("REPORT_JOB")).allowed).toBe(true);
    await svc.setKillSwitch(admin, { switch: "SCAN_STARTS", enabled: false, confirm: true });
    expect((await svc.checkWork("SCAN_START")).allowed).toBe(true);
  });
});

describe("production configuration service (§16/§17)", () => {
  it("evaluates without throwing and never echoes secret values", () => {
    const svc = new ProductionConfigurationService();
    const report = svc.evaluate();
    expect(report).toHaveProperty("ok");
    expect(JSON.stringify(report)).not.toContain(process.env.JWT_SECRET ?? " never");
  });
});

describe("backup orchestrator (§160–§171)", () => {
  it("refuses kinds with no in-platform executor", async () => {
    const db = makeDb();
    const svc = new BackupService(db as never, new AuditService(db as never));
    await expect(svc.startBackup(admin, { kind: "OBJECT_STORAGE" })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("records an honest FAILED run when pg_dump is unavailable — never a fake success", async () => {
    process.env.DATABASE_URL = "postgresql://zerosweep@127.0.0.1:54329/zerosweep";
    const prevBin = process.env.PG_BIN_DIR;
    const prevDir = process.env.PLATFORM_BACKUP_DIR;
    process.env.PG_BIN_DIR = "/nonexistent-pg-bin";
    process.env.PLATFORM_BACKUP_DIR = "/tmp/zerosweep-test-backups";
    try {
      const db = makeDb();
      const svc = new BackupService(db as never, new AuditService(db as never));
      const record = await svc.startBackup(admin, { kind: "POSTGRES" });
      expect(record.status).toBe("FAILED");
      expect(record.errorSummary).toBeTruthy();
      const actions = db.auditLog.rows.map((r) => r.action);
      expect(actions).toContain("BACKUP_STARTED");
      expect(actions).toContain("BACKUP_FAILED");
    } finally {
      if (prevBin === undefined) delete process.env.PG_BIN_DIR; else process.env.PG_BIN_DIR = prevBin;
      if (prevDir === undefined) delete process.env.PLATFORM_BACKUP_DIR; else process.env.PLATFORM_BACKUP_DIR = prevDir;
    }
  });
});

describe("backup encryption fail-closed (§166)", () => {
  it("refuses to write any dump without a passphrase file or into /tmp — recorded FAILED, never plaintext", async () => {
    process.env.DATABASE_URL = "postgresql://zerosweep@127.0.0.1:54329/zerosweep";
    const prevDir = process.env.PLATFORM_BACKUP_DIR;
    const prevPass = process.env.PLATFORM_BACKUP_PASSPHRASE_FILE;
    delete process.env.PLATFORM_BACKUP_PASSPHRASE_FILE;
    try {
      // Private directory, but no encryption configured -> fail closed.
      process.env.PLATFORM_BACKUP_DIR = "/var/backups/zerosweep-test";
      const db = makeDb();
      const svc = new BackupService(db as never, new AuditService(db as never));
      const record = await svc.startBackup(admin, { kind: "POSTGRES" });
      expect(record.status).toBe("FAILED");
      expect(record.errorSummary).toMatch(/encrypt/i);
      expect((record as Row).reference).toBeUndefined();
      // Predictable shared /tmp directory -> fail closed even before dump.
      process.env.PLATFORM_BACKUP_DIR = "/tmp/zerosweep-test-backups";
      process.env.PLATFORM_BACKUP_PASSPHRASE_FILE = "/nonexistent/passphrase";
      const db2 = makeDb();
      const svc2 = new BackupService(db2 as never, new AuditService(db2 as never));
      const record2 = await svc2.startBackup(admin, { kind: "POSTGRES" });
      expect(record2.status).toBe("FAILED");
      expect(record2.errorSummary).toMatch(/\/tmp/);
      // listBackups never discloses the artifact path.
      const listed = await svc.listBackups(admin);
      expect(listed.items.every((b: Row) => !("reference" in b))).toBe(true);
    } finally {
      if (prevDir === undefined) delete process.env.PLATFORM_BACKUP_DIR; else process.env.PLATFORM_BACKUP_DIR = prevDir;
      if (prevPass === undefined) delete process.env.PLATFORM_BACKUP_PASSPHRASE_FILE; else process.env.PLATFORM_BACKUP_PASSPHRASE_FILE = prevPass;
    }
  });

  it("tenant roles cannot start backups at all", async () => {
    const db = makeDb();
    const svc = new BackupService(db as never, new AuditService(db as never));
    await expect(svc.startBackup(tenantAdmin, { kind: "POSTGRES" })).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe("restore orchestrator (§172–§175/§202)", () => {
  const completedBackup = {
    id: "bk-1", kind: "POSTGRES", status: "COMPLETED", reference: "/tmp/nope.dump",
    checksumSha256: "abc", encrypted: false, startedAt: new Date(),
  };

  it("requires RUN_RESTORE (platform admin) and the typed confirmation", async () => {
    const db = makeDb();
    db.platformBackup.rows.push({ ...completedBackup });
    const svc = new BackupService(db as never, new AuditService(db as never));
    // A tenant ADMIN without the platform-admin flag cannot restore.
    await expect(svc.restore(tenantAdmin, "bk-1", { targetDatabase: "zerosweep_restore", confirm: "RESTORE_INTO_ISOLATED_ENVIRONMENT" }))
      .rejects.toBeInstanceOf(ForbiddenException);
    await expect(svc.restore(owner, "bk-1", { targetDatabase: "zerosweep_restore", confirm: "yes" }))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it("refuses production and non-isolated targets before touching anything", async () => {
    process.env.DATABASE_URL = "postgresql://zerosweep@127.0.0.1:54329/zerosweep";
    const db = makeDb();
    db.platformBackup.rows.push({ ...completedBackup });
    const svc = new BackupService(db as never, new AuditService(db as never));
    await expect(svc.restore(owner, "bk-1", { targetDatabase: "zerosweep", confirm: "RESTORE_INTO_ISOLATED_ENVIRONMENT" }))
      .rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.restore(owner, "bk-1", { targetDatabase: "zerosweep_copy", confirm: "RESTORE_INTO_ISOLATED_ENVIRONMENT" }))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(db.platformRestore.rows).toHaveLength(0);
  });

  it("fails the restore record (integrity) when the artifact is missing/corrupt — production untouched", async () => {
    process.env.DATABASE_URL = "postgresql://zerosweep@127.0.0.1:54329/zerosweep";
    const db = makeDb();
    db.platformBackup.rows.push({ ...completedBackup });
    const svc = new BackupService(db as never, new AuditService(db as never));
    const done = await svc.restore(owner, "bk-1", { targetDatabase: "zerosweep_restore", confirm: "RESTORE_INTO_ISOLATED_ENVIRONMENT" });
    expect(done.status).toBe("FAILED");
    expect(db.auditLog.rows.map((r) => r.action)).toContain("RESTORE_FAILED");
  });
});

describe("overview: workers + SLOs (§197–§199, §124–§127)", () => {
  function makeOverview(db: ReturnType<typeof makeDb>) {
    const audit = new AuditService(db as never);
    const health = { check: async () => ({ status: "ok", checks: {} }) } as never;
    const queue = { adminSnapshot: async () => [] } as never;
    return new PlatformOverviewService(db as never, audit, health, queue, makeControl(db), new ProductionConfigurationService());
  }

  it("derives worker status from heartbeat age, never from the stored row", async () => {
    const db = makeDb();
    db.workerNode.rows.push({
      id: "w1", workerId: "w-1", hostname: "h", version: "1", workerType: "GENERAL_WORKER",
      capabilities: [], activeJobs: 0, status: "ONLINE", lastHeartbeat: new Date(Date.now() - 3_600_000),
    });
    const { items } = await makeOverview(db).listWorkers(admin);
    expect(items[0]!.status).toBe("OFFLINE");
  });

  it("SLOs seed defaults and report INSUFFICIENT_DATA with no measured rows", async () => {
    const db = makeDb();
    const { items } = await makeOverview(db).listSlos(secAdmin);
    expect(items.length).toBeGreaterThanOrEqual(3);
    expect(items.every((i) => i.result.status === "INSUFFICIENT_DATA")).toBe(true);
    expect(items.every((i) => i.result.ratio === null)).toBe(true);
    // Unmeasurable kinds are reported, not omitted (§124/§127).
    expect(items.some((i) => i.kind === "API_AVAILABILITY")).toBe(true);
  });

  it("deployment records require a real commit SHA (§147/§156)", async () => {
    const db = makeDb();
    const svc = makeOverview(db);
    await expect(svc.recordDeployment(admin, { version: "1.0.0", commit: "not-a-sha" })).rejects.toBeInstanceOf(BadRequestException);
    const rec = await svc.recordDeployment(admin, { version: "1.0.0", commit: "1eb3310", environment: "production" });
    expect(rec.status).toBe("COMPLETED");
    expect(db.auditLog.rows.map((r) => r.action)).toContain("PRODUCTION_DEPLOYMENT_COMPLETED");
  });
});
