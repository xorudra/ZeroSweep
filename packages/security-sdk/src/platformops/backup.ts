import { createHash } from "node:crypto";
import type { BackupStatus, RestoreStatus } from "./types";

/**
 * Backup / restore policy (Prompt 38 §160–§175, §232–§234). A backup is
 * operationally valid only after a restore test (§175) — creation alone
 * proves nothing. Restores are confirmation-gated, integrity-checked
 * BEFORE anything is written, and may only target an ISOLATED recovery
 * environment (§173): restoring over the live production database from
 * this plane is structurally refused (§244).
 */

export interface RetentionPolicy {
  retentionDays: number;
  /** Keep at least this many most-recent backups regardless of age. */
  keepMinimum: number;
}

export const DEFAULT_RETENTION: RetentionPolicy = { retentionDays: 30, keepMinimum: 3 };

export function retentionExpiry(createdAt: Date, policy: RetentionPolicy = DEFAULT_RETENTION): Date {
  return new Date(createdAt.getTime() + policy.retentionDays * 86_400_000);
}

export function isRetentionExpired(b: { createdAt: Date; rank: number }, now: Date, policy: RetentionPolicy = DEFAULT_RETENTION): boolean {
  if (b.rank < policy.keepMinimum) return false; // newest N are always kept
  return retentionExpiry(b.createdAt, policy) <= now;
}

/** Backup record state machine (§171): no skipping, no resurrection. */
const BACKUP_TRANSITIONS: Record<BackupStatus, BackupStatus[]> = {
  STARTED: ["COMPLETED", "FAILED"],
  COMPLETED: [],
  FAILED: [],
};
export function backupTransitionAllowed(from: BackupStatus, to: BackupStatus): boolean {
  return BACKUP_TRANSITIONS[from].includes(to);
}

const RESTORE_TRANSITIONS: Record<RestoreStatus, RestoreStatus[]> = {
  STARTED: ["COMPLETED", "FAILED"],
  COMPLETED: [],
  FAILED: [],
};
export function restoreTransitionAllowed(from: RestoreStatus, to: RestoreStatus): boolean {
  return RESTORE_TRANSITIONS[from].includes(to);
}

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** §234: a backup whose bytes do not match its recorded checksum is
 *  corrupt — restore refuses BEFORE any target is touched. */
export type IntegrityVerdict = { ok: true } | { ok: false; reason: string };
export function verifyBackupIntegrity(recordedChecksum: string | null, actualChecksum: string): IntegrityVerdict {
  if (!recordedChecksum) return { ok: false, reason: "backup has no recorded checksum — integrity cannot be established" };
  if (recordedChecksum.toLowerCase() !== actualChecksum.toLowerCase()) {
    return { ok: false, reason: "checksum mismatch — backup is corrupt or was tampered with; restore refused" };
  }
  return { ok: true };
}

/** The exact confirmation an operator must type (§172/§202). Anything
 *  else — including a boolean true — is not confirmation. */
export const RESTORE_CONFIRMATION = "RESTORE_INTO_ISOLATED_ENVIRONMENT";

/**
 * §173/§244: the restore target must be an isolated recovery database.
 * It is refused when it names the live production database, a system
 * database, or anything that is not an explicitly-marked recovery
 * target (`*_restore`, `*_recovery`, `*_dr` suffix).
 */
export function evaluateRestoreTarget(input: { targetDatabase: string; productionDatabase: string }): IntegrityVerdict {
  const target = input.targetDatabase.trim();
  if (!target) return { ok: false, reason: "restore target database is required" };
  if (target === input.productionDatabase) {
    return { ok: false, reason: "restore target IS the production database — restores go to an isolated recovery environment first (§173)" };
  }
  if (["postgres", "template0", "template1"].includes(target)) {
    return { ok: false, reason: "restore target is a system database" };
  }
  if (!/(_restore|_recovery|_dr)$/.test(target)) {
    return { ok: false, reason: "restore target must be an isolated recovery database (name must end in _restore, _recovery or _dr)" };
  }
  return { ok: true };
}

/** Restore validation (§174): every check must pass; results are
 *  recorded on the restore record verbatim — never summarised into a
 *  pass the data does not support. */
export interface RestoreValidationChecks {
  databaseConsistent: boolean;
  objectReferencesValid: boolean;
  reportAccessValid: boolean;
  findingHistoryPresent: boolean;
  tenantIsolationIntact: boolean;
}
export function restoreValidationPassed(c: RestoreValidationChecks): boolean {
  return Object.values(c).every(Boolean);
}

/** §180: RPO/RTO exist only as MEASURED values from a DR exercise.
 *  Targets are configuration; achievements are measurements; the two
 *  never mix. */
export interface DrObjectives {
  targetRpoSeconds?: number;
  targetRtoSeconds?: number;
  measuredRpoSeconds?: number;
  measuredRtoSeconds?: number;
}
export function drAchievement(o: DrObjectives): { rpo: string; rto: string } {
  const fmt = (measured?: number, target?: number) =>
    measured === undefined
      ? "NOT_MEASURED"
      : target !== undefined && measured > target
        ? "MEASURED_ABOVE_TARGET"
        : "MEASURED";
  return { rpo: fmt(o.measuredRpoSeconds, o.targetRpoSeconds), rto: fmt(o.measuredRtoSeconds, o.targetRtoSeconds) };
}
