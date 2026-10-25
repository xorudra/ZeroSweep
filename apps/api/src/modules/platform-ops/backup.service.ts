import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { execFile } from "node:child_process";
import { createReadStream } from "node:fs";
import { mkdir, readFile, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  RESTORE_CONFIRMATION, evaluateRestoreTarget, retentionExpiry, sha256Hex,
  verifyBackupIntegrity, type RestoreValidationChecks,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { AuditService } from "../audit/audit.service";
import { requirePlatformPermission } from "./permissions";

const run = promisify(execFile);

/**
 * BackupOrchestrator + RestoreOrchestrator (Prompt 38 §160–§175).
 *
 * Backups: logical PostgreSQL dumps via pg_dump with FIXED argv (this
 * is internal platform code — no client input ever reaches a command
 * line), mandatory AES-256 encryption (§166) into a dedicated private
 * non-/tmp directory with owner-only permissions, SHA-256 checksum,
 * and a full status record (§171). Encryption and a private directory
 * are fail-closed preconditions: without them no dump is written and
 * the run is recorded FAILED — never a plaintext success. If the
 * tooling is unavailable the run is likewise recorded FAILED with the
 * reason — never as a success that did not happen. Artifact paths are
 * internal and are never returned to API callers.
 *
 * Restores: OWNER-only (RUN_RESTORE), typed confirmation (§202),
 * checksum verified BEFORE any write (§234), target must be an
 * isolated recovery database (§173) — restoring over production from
 * this plane is structurally refused. Validation results (§174) are
 * recorded verbatim. Secrets never enter records or errors (§163).
 */
@Injectable()
export class BackupService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private tool(name: string): string {
    const dir = process.env.PG_BIN_DIR;
    return dir ? join(dir, name) : name;
  }

  private backupDir(): string {
    return process.env.PLATFORM_BACKUP_DIR ?? "/var/backups/zerosweep";
  }

  /** Fail-closed backup preconditions: encryption passphrase configured
   *  and a dedicated private directory outside shared /tmp. Throws
   *  before any dump bytes are written. */
  private assertBackupConfig(dir: string): string {
    const passphraseFile = process.env.PLATFORM_BACKUP_PASSPHRASE_FILE;
    if (!passphraseFile) {
      throw new Error("backup refused: PLATFORM_BACKUP_PASSPHRASE_FILE is not configured — backups are encrypted by default and never written in plaintext (§166)");
    }
    const normalized = dir.replace(/\/+$/, "");
    if (normalized === "/tmp" || normalized.startsWith("/tmp/")) {
      throw new Error("backup refused: PLATFORM_BACKUP_DIR must be a dedicated private directory outside /tmp — plaintext or encrypted dumps never land on a predictable shared path");
    }
    return passphraseFile;
  }

  private conn(): { host: string; port: string; user: string; password?: string; database: string } {
    const url = new URL(process.env.DATABASE_URL ?? "");
    return {
      host: url.hostname || "127.0.0.1",
      port: url.port || "5432",
      user: decodeURIComponent(url.username || "postgres"),
      password: url.password ? decodeURIComponent(url.password) : undefined,
      database: url.pathname.replace(/^\//, "") || "postgres",
    };
  }

  private sanitize(message: string): string {
    let out = message;
    if (process.env.DATABASE_URL) out = out.split(process.env.DATABASE_URL).join("[database-url]");
    const pw = this.conn().password;
    if (pw) out = out.split(pw).join("[redacted]");
    return out.slice(0, 500);
  }

  async listBackups(user: RequestUser) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    const items = await this.prisma.platformBackup.findMany({ orderBy: { startedAt: "desc" }, take: 50 });
    // The artifact path (reference) is an internal filesystem location —
    // never disclosed in API responses.
    return { items: items.map((b) => { const { reference: _ref, ...rest } = b as typeof b & { reference?: unknown }; return { ...rest, sizeBytes: b.sizeBytes?.toString() ?? null }; }) };
  }

  async startBackup(user: RequestUser, input: { kind?: string }) {
    requirePlatformPermission(user, "MANAGE_BACKUPS");
    const kind = input.kind ?? "POSTGRES";
    if (kind !== "POSTGRES") {
      throw new BadRequestException(
        `backup kind ${kind} has no in-platform executor — object-storage and provider-native backups run through the provider (§164) and are recorded by their own tooling`,
      );
    }
    const startedAt = new Date();
    const record = await this.prisma.platformBackup.create({
      data: { kind, status: "STARTED", createdById: user.id, startedAt, retentionExpiresAt: retentionExpiry(startedAt) },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: "BACKUP_STARTED", resourceType: "PlatformBackup", resourceId: record.id, metadata: { kind },
    });
    const done = await this.executeBackup(record.id, startedAt);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: done.status === "COMPLETED" ? "BACKUP_COMPLETED" : "BACKUP_FAILED",
      resourceType: "PlatformBackup", resourceId: record.id,
      metadata: { kind, ...(done.errorSummary ? { error: done.errorSummary } : {}) },
    });
    const { reference: _ref, ...safe } = done as typeof done & { reference?: unknown };
    return { ...safe, sizeBytes: done.sizeBytes?.toString() ?? null };
  }

  private async executeBackup(id: string, startedAt: Date) {
    const dir = this.backupDir();
    const stamp = startedAt.toISOString().replace(/[:.]/g, "-");
    let artifact = join(dir, `zerosweep-pg-${stamp}-${id}.dump`);
    let encrypted = false;
    try {
      // Fail closed BEFORE any dump is written: encryption + private dir.
      const passphraseFile = this.assertBackupConfig(dir);
      const c = this.conn();
      await mkdir(dir, { recursive: true, mode: 0o700 });
      const env = { ...process.env, ...(c.password ? { PGPASSWORD: c.password } : {}) };
      await run(this.tool("pg_dump"), [
        "-h", c.host, "-p", c.port, "-U", c.user, "-d", c.database,
        "-Fc", "--no-owner", "-f", artifact,
      ], { env, timeout: 600_000, maxBuffer: 16 * 1024 * 1024 });

      // Encryption is mandatory, not opt-in: the plaintext dump is
      // always replaced by its AES-256 ciphertext and unlinked.
      const encPath = `${artifact}.enc`;
      await run("openssl", [
        "enc", "-aes-256-cbc", "-salt", "-pbkdf2",
        "-pass", `file:${passphraseFile}`, "-in", artifact, "-out", encPath,
      ], { timeout: 120_000 });
      await unlink(artifact);
      artifact = encPath;
      encrypted = true;
      const bytes = await readFile(artifact);
      const checksum = sha256Hex(bytes);
      const st = await stat(artifact);
      return await this.prisma.platformBackup.update({
        where: { id },
        data: {
          status: "COMPLETED", sizeBytes: BigInt(st.size), durationMs: Date.now() - startedAt.getTime(),
          reference: artifact, checksumSha256: checksum, encrypted, completedAt: new Date(),
        },
      });
    } catch (e) {
      // Never leave a plaintext (or partial) dump behind on failure.
      if (!encrypted) await unlink(artifact).catch(() => undefined);
      return await this.prisma.platformBackup.update({
        where: { id },
        data: {
          status: "FAILED", durationMs: Date.now() - startedAt.getTime(), completedAt: new Date(),
          errorSummary: this.sanitize(e instanceof Error ? e.message : "backup failed"),
        },
      });
    }
  }

  async restore(user: RequestUser, backupId: string, input: { targetDatabase?: string; confirm?: string; isRestoreTest?: boolean }) {
    requirePlatformPermission(user, "RUN_RESTORE");
    if (input.confirm !== RESTORE_CONFIRMATION) {
      throw new BadRequestException(`restore requires the typed confirmation "${RESTORE_CONFIRMATION}" (§172/§202)`);
    }
    const backup = await this.prisma.platformBackup.findUnique({ where: { id: backupId } });
    if (!backup) throw new NotFoundException("backup not found");
    if (backup.status !== "COMPLETED" || !backup.reference || !backup.checksumSha256) {
      throw new BadRequestException("only a COMPLETED backup with a recorded checksum can be restored");
    }
    const target = (input.targetDatabase ?? "").trim();
    if (!/^[a-z][a-z0-9_]*$/.test(target)) {
      throw new BadRequestException("restore target must be a plain database identifier");
    }
    const verdict = evaluateRestoreTarget({ targetDatabase: target, productionDatabase: this.conn().database });
    if (!verdict.ok) throw new BadRequestException(verdict.reason);

    const record = await this.prisma.platformRestore.create({
      data: { backupId, status: "STARTED", targetDatabase: target, isRestoreTest: input.isRestoreTest !== false, startedById: user.id },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: "RESTORE_STARTED", resourceType: "PlatformRestore", resourceId: record.id,
      metadata: { backupId, targetDatabase: target },
    });
    const done = await this.executeRestore(record.id, backup, target);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: done.status === "COMPLETED" ? "RESTORE_COMPLETED" : "RESTORE_FAILED",
      resourceType: "PlatformRestore", resourceId: record.id,
      metadata: { backupId, targetDatabase: target, ...(done.errorSummary ? { error: done.errorSummary } : {}) },
    });
    return done;
  }

  private async fileChecksum(path: string): Promise<string> {
    const hash = (await import("node:crypto")).createHash("sha256");
    await new Promise<void>((resolve, reject) => {
      const s = createReadStream(path);
      s.on("data", (d) => hash.update(d as Buffer));
      s.on("end", resolve);
      s.on("error", reject);
    });
    return hash.digest("hex");
  }

  private async executeRestore(id: string, backup: { reference: string | null; checksumSha256: string | null; encrypted: boolean }, target: string) {
    const fail = async (errorSummary: string) => this.prisma.platformRestore.update({
      where: { id }, data: { status: "FAILED", errorSummary: this.sanitize(errorSummary), completedAt: new Date() },
    });
    const c = this.conn();
    const env = { ...process.env, ...(c.password ? { PGPASSWORD: c.password } : {}) };
    let plainPath = backup.reference!;
    let tempPlain: string | null = null;
    try {
      // §234: integrity BEFORE anything is created or written.
      const actual = await this.fileChecksum(plainPath);
      const integrity = verifyBackupIntegrity(backup.checksumSha256, actual);
      if (!integrity.ok) return fail(integrity.reason);

      if (backup.encrypted) {
        const passphraseFile = process.env.PLATFORM_BACKUP_PASSPHRASE_FILE;
        if (!passphraseFile) return fail("backup is encrypted but PLATFORM_BACKUP_PASSPHRASE_FILE is not configured on this instance");
        tempPlain = `${plainPath}.dec-${id}`;
        await run("openssl", [
          "enc", "-d", "-aes-256-cbc", "-pbkdf2",
          "-pass", `file:${passphraseFile}`, "-in", plainPath, "-out", tempPlain,
        ], { timeout: 120_000 });
        plainPath = tempPlain;
      }

      await run(this.tool("psql"), [
        "-h", c.host, "-p", c.port, "-U", c.user, "-d", "postgres",
        "-v", "ON_ERROR_STOP=1", "-c", `CREATE DATABASE "${target}"`,
      ], { env, timeout: 60_000 });
      await run(this.tool("pg_restore"), [
        "-h", c.host, "-p", c.port, "-U", c.user, "-d", target,
        "--no-owner", "--exit-on-error", plainPath,
      ], { env, timeout: 600_000, maxBuffer: 16 * 1024 * 1024 });

      const validation = await this.validateRestored(env, target);
      const passed = Object.values(validation).every(Boolean);
      return await this.prisma.platformRestore.update({
        where: { id },
        data: {
          status: passed ? "COMPLETED" : "FAILED",
          validation: validation as never, completedAt: new Date(),
          ...(passed ? {} : { errorSummary: "restore completed but validation checks failed (§174) — see validation record" }),
        },
      });
    } catch (e) {
      return fail(e instanceof Error ? e.message : "restore failed");
    } finally {
      if (tempPlain) await unlink(tempPlain).catch(() => undefined);
      // §175 housekeeping note: the isolated target DB is left in place
      // for operator inspection; dropping it is an operator action.
    }
  }

  private async validateRestored(env: NodeJS.ProcessEnv, target: string): Promise<RestoreValidationChecks> {
    const c = this.conn();
    const sql = `SELECT json_build_object(
      'databaseConsistent', NOT EXISTS (SELECT 1 FROM "Finding" f LEFT JOIN "Workspace" w ON f."workspaceId" = w.id WHERE w.id IS NULL),
      'objectReferencesValid', NOT EXISTS (SELECT 1 FROM "PacketCaptureArtifact" WHERE "storageKey" IS NULL OR "storageKey" = ''),
      'reportAccessValid', NOT EXISTS (SELECT 1 FROM "Report" r LEFT JOIN "Scan" s ON r."scanId" = s.id WHERE s.id IS NULL),
      'findingHistoryPresent', (SELECT COUNT(*) FROM "FindingHistory") >= 0,
      'tenantIsolationIntact', NOT EXISTS (SELECT 1 FROM "Workspace" w LEFT JOIN "Organization" o ON w."organizationId" = o.id WHERE o.id IS NULL)
    )::text`;
    const { stdout } = await run(this.tool("psql"), [
      "-h", c.host, "-p", c.port, "-U", c.user, "-d", target,
      "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", sql,
    ], { env, timeout: 60_000 });
    return JSON.parse(stdout.trim()) as RestoreValidationChecks;
  }

  async listRestores(user: RequestUser, backupId: string) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    const items = await this.prisma.platformRestore.findMany({
      where: { backupId }, orderBy: { startedAt: "desc" }, take: 20,
    });
    return { items };
  }
}
