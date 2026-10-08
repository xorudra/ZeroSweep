import { Body, Controller, Get, Param, Post } from "@nestjs/common";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { PlatformControlService } from "./platform-control.service";
import { PlatformOverviewService } from "./platform-overview.service";
import { BackupService } from "./backup.service";
import { ProductionConfigurationService } from "./production-config.service";
import { requirePlatformPermission } from "./permissions";

/**
 * Platform operations API (Prompt 38 §197–§204). Every route is behind
 * platform RBAC (§203); dangerous operations (maintenance, kill
 * switches, restore) additionally require explicit confirmation and
 * are audited (§202/§204). There is deliberately NO route that runs a
 * shell command, edits a target system, or restores over production.
 */
@Controller("platform")
export class PlatformController {
  constructor(
    private readonly overviewSvc: PlatformOverviewService,
    private readonly control: PlatformControlService,
    private readonly backups: BackupService,
    private readonly productionConfig: ProductionConfigurationService,
  ) {}

  @Get("overview")
  overview(@CurrentUser() user: RequestUser) {
    return this.overviewSvc.overview(user);
  }

  @Get("config/validation")
  configValidation(@CurrentUser() user: RequestUser) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    return this.productionConfig.evaluate();
  }

  @Get("control")
  async getControl(@CurrentUser() user: RequestUser) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    return this.control.getState();
  }

  @Post("control/maintenance")
  setMaintenance(@CurrentUser() user: RequestUser, @Body() body: { enabled: boolean; message?: string; confirm?: boolean }) {
    return this.control.setMaintenance(user, body ?? { enabled: false });
  }

  @Post("control/kill-switch")
  setKillSwitch(@CurrentUser() user: RequestUser, @Body() body: { switch: string; enabled: boolean; reason?: string; confirm?: boolean }) {
    return this.control.setKillSwitch(user, body ?? { switch: "", enabled: false });
  }

  @Get("queues")
  queues(@CurrentUser() user: RequestUser) {
    return this.overviewSvc.queues(user);
  }

  @Get("queues/:name/failed")
  failedJobs(@CurrentUser() user: RequestUser, @Param("name") name: string) {
    return this.overviewSvc.failedJobs(user, name);
  }

  @Post("queues/:name/jobs/:jobId/retry")
  retryJob(@CurrentUser() user: RequestUser, @Param("name") name: string, @Param("jobId") jobId: string) {
    return this.overviewSvc.retryJob(user, name, jobId);
  }

  @Post("queues/:name/jobs/:jobId/cancel")
  cancelJob(@CurrentUser() user: RequestUser, @Param("name") name: string, @Param("jobId") jobId: string) {
    return this.overviewSvc.cancelJob(user, name, jobId);
  }

  @Get("workers")
  workers(@CurrentUser() user: RequestUser) {
    return this.overviewSvc.listWorkers(user);
  }

  @Get("backups")
  listBackups(@CurrentUser() user: RequestUser) {
    return this.backups.listBackups(user);
  }

  @Post("backups")
  startBackup(@CurrentUser() user: RequestUser, @Body() body: { kind?: string }) {
    return this.backups.startBackup(user, body ?? {});
  }

  @Get("backups/:id/restores")
  listRestores(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.backups.listRestores(user, id);
  }

  @Post("backups/:id/restore")
  restore(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: { targetDatabase?: string; confirm?: string; isRestoreTest?: boolean }) {
    return this.backups.restore(user, id, body ?? {});
  }

  @Get("slos")
  slos(@CurrentUser() user: RequestUser) {
    return this.overviewSvc.listSlos(user);
  }

  @Get("deployments")
  deployments(@CurrentUser() user: RequestUser) {
    return this.overviewSvc.listDeployments(user);
  }

  @Post("deployments")
  recordDeployment(@CurrentUser() user: RequestUser, @Body() body: {
    version?: string; commit?: string; build?: string; migrationVersion?: string;
    environment?: string; notes?: string; rollback?: boolean;
  }) {
    return this.overviewSvc.recordDeployment(user, body ?? {});
  }

  @Post("dr-exercises")
  recordDrExercise(@CurrentUser() user: RequestUser, @Body() body: {
    scenario?: string; measuredRpoSeconds?: number; measuredRtoSeconds?: number;
    targetRpoSeconds?: number; targetRtoSeconds?: number; issues?: string;
  }) {
    return this.overviewSvc.recordDrExercise(user, body ?? {});
  }
}
