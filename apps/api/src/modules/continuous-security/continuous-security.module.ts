import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { VulnerabilityManagementModule } from "../vulnerability-management/vulnerability-management.module";
import { SecurityValidationModule } from "../security-validation/security-validation.module";
import { VulnerabilitiesModule } from "../vulnerabilities/vulnerabilities.module";
import {
  AttackSurfaceController, DriftController, MonitoringController, NotificationsController,
  PostureController, SchedulesController, WorkflowsController,
} from "./continuous-security.controller";
import { MonitoringPolicyService } from "./monitoring/monitoring-policy.service";
import { SecuritySchedulerService } from "./schedules/security-scheduler.service";
import { SnapshotService } from "./snapshots/snapshot.service";
import { DriftService } from "./drift/drift.service";
import { WorkflowService } from "./workflows/workflow.service";
import { NotificationRouterService } from "./notifications/notification-router.service";
import { AutoRetestService } from "./retesting/auto-retest.service";
import { MonitoringAnalyticsService } from "./analytics/monitoring-analytics.service";

/**
 * Prompt 22 — Continuous Security Monitoring, Intelligent Scheduler &
 * Change Detection. The scheduler materializes work ONLY through the
 * existing governed modules (orchestration, reporting, validation,
 * retests) — imported here, never reimplemented.
 */
@Module({
  imports: [AuditModule, OrchestrationModule, VulnerabilityManagementModule, SecurityValidationModule, VulnerabilitiesModule],
  controllers: [
    MonitoringController, SchedulesController, PostureController, DriftController,
    AttackSurfaceController, WorkflowsController, NotificationsController,
  ],
  providers: [
    MonitoringPolicyService, SecuritySchedulerService, SnapshotService, DriftService,
    WorkflowService, NotificationRouterService, AutoRetestService, MonitoringAnalyticsService,
  ],
  exports: [SecuritySchedulerService, SnapshotService, DriftService, WorkflowService, NotificationRouterService],
})
export class ContinuousSecurityModule {}
