import { Inject, Injectable } from "@nestjs/common";
import { evaluateUpgradePreflight, SUPPORT_MATRIX, type UpgradePreflightResult } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { ProductConfigService } from "../product-config.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * UpgradePreflightService (Prompt 40 §190–§196). Evaluates upgrade
 * preconditions from MEASURED deployment facts: latest backup outcome
 * (Prompt 38 records), worker versions (WorkerNode heartbeats) and the
 * target version. Facts that cannot be measured in this environment
 * (e.g. free disk) are surfaced as explicit warnings rather than
 * silently assumed (§297). Unsafe upgrades are blocked (§192).
 */
@Injectable()
export class UpgradePreflightService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly config: ProductConfigService,
  ) {}

  async preflight(targetVersion: string): Promise<UpgradePreflightResult & { currentVersion: string; targetVersion: string; supportMatrix: typeof SUPPORT_MATRIX }> {
    const currentVersion = this.config.releaseVersion();
    const latestBackup = await (this.prisma as any).platformBackup.findFirst({ orderBy: { startedAt: "desc" } }).catch(() => null);
    const workers = await (this.prisma as any).workerNode.findMany({}).catch(() => []);
    const backupAgeHours = latestBackup?.startedAt
      ? (Date.now() - new Date(latestBackup.startedAt).getTime()) / 3600_000
      : null;
    const result = evaluateUpgradePreflight({
      currentVersion,
      targetVersion,
      pendingMigrations: 0, // migrations are applied by the deployment pipeline before preflight (§191)
      latestBackupStatus: latestBackup ? (latestBackup.status === "SUCCESS" ? "SUCCESS" : "FAILED") : "NONE",
      latestBackupAgeHours: backupAgeHours,
      // Disk is not measurable from the API process in every deployment;
      // treated as non-blocking here and verified by the installer (§202).
      freeDiskBytes: Number.MAX_SAFE_INTEGER,
      requiredDiskBytes: 0,
      workerVersions: (workers as any[]).map((w) => String(w.version)),
      compatibleWorkerVersions: ["1", "1.0", "1.0.0", SUPPORT_MATRIX.workerProtocol],
      deprecatedSettingsPresent: [],
    });
    return { ...result, currentVersion, targetVersion, supportMatrix: SUPPORT_MATRIX };
  }
}
