-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'MONITORING_POLICY_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'MONITORING_POLICY_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'MONITORING_POLICY_DELETED';
ALTER TYPE "AuditAction" ADD VALUE 'SCHEDULE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCHEDULE_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCHEDULE_DELETED';
ALTER TYPE "AuditAction" ADD VALUE 'SCHEDULE_PAUSED';
ALTER TYPE "AuditAction" ADD VALUE 'SCHEDULE_RESUMED';
ALTER TYPE "AuditAction" ADD VALUE 'SCHEDULE_RUN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'SCHEDULE_RUN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'SCHEDULE_RUN_BLOCKED';
ALTER TYPE "AuditAction" ADD VALUE 'POSTURE_SNAPSHOT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'ASSET_DRIFT_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_DRIFT_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_DRIFT_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'AUTO_RETEST_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'WORKFLOW_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'WORKFLOW_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'WORKFLOW_TRIGGERED';
ALTER TYPE "AuditAction" ADD VALUE 'WORKFLOW_ACTION_EXECUTED';
ALTER TYPE "AuditAction" ADD VALUE 'NOTIFICATION_SENT';
ALTER TYPE "AuditAction" ADD VALUE 'NOTIFICATION_POLICY_UPDATED';

-- CreateTable
CREATE TABLE "MonitoringPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "targetSelector" JSONB NOT NULL DEFAULT '{}',
    "scanProfile" TEXT NOT NULL,
    "frequency" TEXT NOT NULL DEFAULT 'DAILY',
    "cronExpression" TEXT,
    "timezone" TEXT NOT NULL DEFAULT 'UTC',
    "safeOnly" BOOLEAN NOT NULL DEFAULT true,
    "riskThreshold" DOUBLE PRECISION,
    "retestPolicy" JSONB NOT NULL DEFAULT '{}',
    "notificationPolicy" JSONB NOT NULL DEFAULT '{}',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MonitoringPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecuritySchedule" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "policyId" TEXT,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'SCAN',
    "assessmentId" TEXT,
    "reportScheduleId" TEXT,
    "profile" TEXT,
    "expression" TEXT NOT NULL,
    "frequency" TEXT NOT NULL DEFAULT 'DAILY',
    "timezone" TEXT NOT NULL DEFAULT 'UTC',
    "nextRunAt" TIMESTAMP(3) NOT NULL,
    "lastRunAt" TIMESTAMP(3),
    "lastStatus" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "paused" BOOLEAN NOT NULL DEFAULT false,
    "failureCount" INTEGER NOT NULL DEFAULT 0,
    "missedRunPolicy" TEXT NOT NULL DEFAULT 'RUN_ONCE',
    "allowConcurrent" BOOLEAN NOT NULL DEFAULT false,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecuritySchedule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScheduleRun" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scheduleId" TEXT NOT NULL,
    "scheduleRunKey" TEXT NOT NULL,
    "scheduledFor" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL,
    "reasonCode" TEXT,
    "reason" TEXT,
    "scanId" TEXT,
    "reportId" TEXT,
    "validationRequestId" TEXT,
    "retestRequestId" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3),
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScheduleRun_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SchedulerLease" (
    "id" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "owner" TEXT NOT NULL,
    "leaseUntil" TIMESTAMP(3) NOT NULL,
    "heartbeatAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SchedulerLease_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SchedulerSettings" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "maxConcurrentScheduledScans" INTEGER NOT NULL DEFAULT 2,
    "dailyRunBudget" INTEGER NOT NULL DEFAULT 200,
    "queueDepthThreshold" INTEGER NOT NULL DEFAULT 100,
    "leaseTtlSeconds" INTEGER NOT NULL DEFAULT 120,
    "maxRetryAttempts" INTEGER NOT NULL DEFAULT 3,
    "updatedBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SchedulerSettings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MaintenanceWindow" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "policyId" TEXT,
    "name" TEXT NOT NULL,
    "daysOfWeek" JSONB NOT NULL DEFAULT '[]',
    "startTime" TEXT NOT NULL,
    "endTime" TEXT NOT NULL,
    "timezone" TEXT NOT NULL DEFAULT 'UTC',
    "mode" TEXT NOT NULL DEFAULT 'ALLOWED_HOURS',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MaintenanceWindow_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlackoutWindow" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "reason" TEXT,
    "startsAt" TIMESTAMP(3) NOT NULL,
    "endsAt" TIMESTAMP(3) NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BlackoutWindow_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityPostureSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT NOT NULL DEFAULT 'SCHEDULED',
    "assetCount" INTEGER NOT NULL,
    "findingCount" INTEGER NOT NULL,
    "findingsBySeverity" JSONB NOT NULL DEFAULT '{}',
    "findingsByStatus" JSONB NOT NULL DEFAULT '{}',
    "kevCount" INTEGER NOT NULL DEFAULT 0,
    "verifiedFindings" INTEGER NOT NULL DEFAULT 0,
    "slaOverdue" INTEGER NOT NULL DEFAULT 0,
    "slaDueSoon" INTEGER NOT NULL DEFAULT 0,
    "coverage" DOUBLE PRECISION,
    "riskScore" DOUBLE PRECISION,
    "contentHash" TEXT NOT NULL,

    CONSTRAINT "SecurityPostureSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssetSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT NOT NULL DEFAULT 'SCHEDULED',
    "entryCount" INTEGER NOT NULL DEFAULT 0,
    "contentHash" TEXT NOT NULL,

    CONSTRAINT "AssetSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssetSnapshotEntry" (
    "id" TEXT NOT NULL,
    "snapshotId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetKey" TEXT NOT NULL,
    "assetId" TEXT,
    "host" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "exposure" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "scopeStatus" TEXT NOT NULL DEFAULT 'IN_SCOPE',
    "criticality" TEXT NOT NULL DEFAULT 'UNSPECIFIED',
    "ports" JSONB NOT NULL DEFAULT '[]',
    "services" JSONB NOT NULL DEFAULT '[]',
    "endpointCount" INTEGER NOT NULL DEFAULT 0,
    "stateHash" TEXT NOT NULL,

    CONSTRAINT "AssetSnapshotEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT NOT NULL DEFAULT 'SCHEDULED',
    "entryCount" INTEGER NOT NULL DEFAULT 0,
    "contentHash" TEXT NOT NULL,

    CONSTRAINT "FindingSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingSnapshotEntry" (
    "id" TEXT NOT NULL,
    "snapshotId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "lifecycleStatus" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "priority" TEXT,
    "riskScore" DOUBLE PRECISION,
    "verificationStatus" TEXT NOT NULL,
    "kevListed" BOOLEAN NOT NULL DEFAULT false,
    "cve" TEXT,
    "stateHash" TEXT NOT NULL,

    CONSTRAINT "FindingSnapshotEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AttackSurfaceChange" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "assetKey" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "priority" TEXT NOT NULL DEFAULT 'NORMAL',
    "detail" TEXT NOT NULL,
    "fromSnapshotId" TEXT,
    "toSnapshotId" TEXT,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AttackSurfaceChange_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "changeType" TEXT NOT NULL,
    "entityKey" TEXT NOT NULL,
    "detail" TEXT NOT NULL,
    "fromValue" JSONB,
    "toValue" JSONB,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingDriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "findingId" TEXT,
    "detail" TEXT NOT NULL,
    "fromValue" JSONB,
    "toValue" JSONB,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingDriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskDriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "findingId" TEXT,
    "cve" TEXT,
    "detail" TEXT NOT NULL,
    "fromValue" JSONB,
    "toValue" JSONB,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RiskDriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AutoRetestPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "triggers" JSONB NOT NULL DEFAULT '[]',
    "maxPerDay" INTEGER NOT NULL DEFAULT 50,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AutoRetestPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityWorkflow" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "trigger" TEXT NOT NULL,
    "conditions" JSONB NOT NULL DEFAULT '[]',
    "actions" JSONB NOT NULL DEFAULT '[]',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "owner" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityWorkflow_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WorkflowExecution" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "workflowId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "trigger" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "actions" JSONB NOT NULL DEFAULT '[]',
    "depth" INTEGER NOT NULL DEFAULT 0,
    "lineage" JSONB NOT NULL DEFAULT '[]',
    "errors" JSONB NOT NULL DEFAULT '[]',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "WorkflowExecution_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NotificationPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "eventTypes" JSONB NOT NULL DEFAULT '[]',
    "minSeverity" TEXT,
    "minPriority" TEXT,
    "riskThreshold" DOUBLE PRECISION,
    "channels" JSONB NOT NULL DEFAULT '["IN_APP"]',
    "recipients" JSONB NOT NULL DEFAULT '[]',
    "dedupWindowMinutes" INTEGER NOT NULL DEFAULT 60,
    "quietHours" JSONB,
    "emergencySeverities" JSONB NOT NULL DEFAULT '["CRITICAL"]',
    "throttlePerHour" INTEGER NOT NULL DEFAULT 60,
    "webhookUrl" TEXT,
    "webhookAllowlist" JSONB NOT NULL DEFAULT '[]',
    "signingSecretRef" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AlertEscalationPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "priorities" JSONB NOT NULL DEFAULT '["P0","P1"]',
    "escalateAfterMinutes" INTEGER NOT NULL DEFAULT 240,
    "escalateTo" JSONB NOT NULL DEFAULT '[]',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AlertEscalationPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityNotification" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "policyId" TEXT,
    "eventType" TEXT NOT NULL,
    "channel" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "providerStatus" TEXT,
    "fingerprint" TEXT NOT NULL,
    "groupKey" TEXT,
    "findingId" TEXT,
    "assetKey" TEXT,
    "title" TEXT NOT NULL,
    "detail" TEXT,
    "escalated" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityNotification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiDailySecuritySummary" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "date" TEXT NOT NULL,
    "snapshotId" TEXT,
    "generator" TEXT NOT NULL DEFAULT 'RULE_BASED',
    "summary" JSONB NOT NULL DEFAULT '{}',
    "citations" JSONB NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiDailySecuritySummary_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "MonitoringPolicy_workspaceId_enabled_idx" ON "MonitoringPolicy"("workspaceId", "enabled");

-- CreateIndex
CREATE INDEX "SecuritySchedule_workspaceId_enabled_idx" ON "SecuritySchedule"("workspaceId", "enabled");

-- CreateIndex
CREATE INDEX "SecuritySchedule_nextRunAt_enabled_idx" ON "SecuritySchedule"("nextRunAt", "enabled");

-- CreateIndex
CREATE UNIQUE INDEX "ScheduleRun_scheduleRunKey_key" ON "ScheduleRun"("scheduleRunKey");

-- CreateIndex
CREATE INDEX "ScheduleRun_workspaceId_scheduleId_idx" ON "ScheduleRun"("workspaceId", "scheduleId");

-- CreateIndex
CREATE INDEX "ScheduleRun_workspaceId_createdAt_idx" ON "ScheduleRun"("workspaceId", "createdAt");

-- CreateIndex
CREATE INDEX "ScheduleRun_status_idx" ON "ScheduleRun"("status");

-- CreateIndex
CREATE UNIQUE INDEX "SchedulerLease_scope_key" ON "SchedulerLease"("scope");

-- CreateIndex
CREATE UNIQUE INDEX "SchedulerSettings_workspaceId_key" ON "SchedulerSettings"("workspaceId");

-- CreateIndex
CREATE INDEX "MaintenanceWindow_workspaceId_idx" ON "MaintenanceWindow"("workspaceId");

-- CreateIndex
CREATE INDEX "BlackoutWindow_workspaceId_startsAt_idx" ON "BlackoutWindow"("workspaceId", "startsAt");

-- CreateIndex
CREATE INDEX "SecurityPostureSnapshot_workspaceId_capturedAt_idx" ON "SecurityPostureSnapshot"("workspaceId", "capturedAt");

-- CreateIndex
CREATE INDEX "AssetSnapshot_workspaceId_capturedAt_idx" ON "AssetSnapshot"("workspaceId", "capturedAt");

-- CreateIndex
CREATE INDEX "AssetSnapshotEntry_snapshotId_idx" ON "AssetSnapshotEntry"("snapshotId");

-- CreateIndex
CREATE INDEX "AssetSnapshotEntry_workspaceId_assetKey_idx" ON "AssetSnapshotEntry"("workspaceId", "assetKey");

-- CreateIndex
CREATE INDEX "FindingSnapshot_workspaceId_capturedAt_idx" ON "FindingSnapshot"("workspaceId", "capturedAt");

-- CreateIndex
CREATE INDEX "FindingSnapshotEntry_snapshotId_idx" ON "FindingSnapshotEntry"("snapshotId");

-- CreateIndex
CREATE INDEX "FindingSnapshotEntry_workspaceId_fingerprint_idx" ON "FindingSnapshotEntry"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "AttackSurfaceChange_workspaceId_detectedAt_idx" ON "AttackSurfaceChange"("workspaceId", "detectedAt");

-- CreateIndex
CREATE INDEX "AttackSurfaceChange_workspaceId_type_idx" ON "AttackSurfaceChange"("workspaceId", "type");

-- CreateIndex
CREATE INDEX "DriftEvent_workspaceId_domain_idx" ON "DriftEvent"("workspaceId", "domain");

-- CreateIndex
CREATE INDEX "DriftEvent_workspaceId_detectedAt_idx" ON "DriftEvent"("workspaceId", "detectedAt");

-- CreateIndex
CREATE INDEX "FindingDriftEvent_workspaceId_detectedAt_idx" ON "FindingDriftEvent"("workspaceId", "detectedAt");

-- CreateIndex
CREATE INDEX "FindingDriftEvent_workspaceId_fingerprint_idx" ON "FindingDriftEvent"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "RiskDriftEvent_workspaceId_detectedAt_idx" ON "RiskDriftEvent"("workspaceId", "detectedAt");

-- CreateIndex
CREATE INDEX "RiskDriftEvent_workspaceId_cve_idx" ON "RiskDriftEvent"("workspaceId", "cve");

-- CreateIndex
CREATE UNIQUE INDEX "AutoRetestPolicy_workspaceId_key" ON "AutoRetestPolicy"("workspaceId");

-- CreateIndex
CREATE INDEX "SecurityWorkflow_workspaceId_trigger_idx" ON "SecurityWorkflow"("workspaceId", "trigger");

-- CreateIndex
CREATE INDEX "SecurityWorkflow_workspaceId_enabled_idx" ON "SecurityWorkflow"("workspaceId", "enabled");

-- CreateIndex
CREATE INDEX "WorkflowExecution_workspaceId_workflowId_idx" ON "WorkflowExecution"("workspaceId", "workflowId");

-- CreateIndex
CREATE INDEX "WorkflowExecution_workspaceId_startedAt_idx" ON "WorkflowExecution"("workspaceId", "startedAt");

-- CreateIndex
CREATE INDEX "NotificationPolicy_workspaceId_enabled_idx" ON "NotificationPolicy"("workspaceId", "enabled");

-- CreateIndex
CREATE INDEX "AlertEscalationPolicy_workspaceId_enabled_idx" ON "AlertEscalationPolicy"("workspaceId", "enabled");

-- CreateIndex
CREATE INDEX "SecurityNotification_workspaceId_createdAt_idx" ON "SecurityNotification"("workspaceId", "createdAt");

-- CreateIndex
CREATE INDEX "SecurityNotification_workspaceId_fingerprint_idx" ON "SecurityNotification"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "AiDailySecuritySummary_workspaceId_createdAt_idx" ON "AiDailySecuritySummary"("workspaceId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "AiDailySecuritySummary_workspaceId_date_key" ON "AiDailySecuritySummary"("workspaceId", "date");

