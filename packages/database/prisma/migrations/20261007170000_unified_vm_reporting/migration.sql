-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "VmLifecycleStatus" ADD VALUE 'REOPENED';
ALTER TYPE "VmLifecycleStatus" ADD VALUE 'DUPLICATE';
ALTER TYPE "VmLifecycleStatus" ADD VALUE 'MITIGATED';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'FINDING_TRIAGED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_ASSIGNED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_STATUS_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_PRIORITY_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_BULK_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'SLA_POLICY_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'SLA_BREACHED';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_EXCEPTION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_EXCEPTION_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_EXCEPTION_EXPIRED';
ALTER TYPE "AuditAction" ADD VALUE 'REPORT_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'REPORT_DOWNLOADED';
ALTER TYPE "AuditAction" ADD VALUE 'EXTERNAL_IMPORT_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'EXTERNAL_IMPORT_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'EXTERNAL_EXPORT_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'INTEGRATION_SYNC_COMPLETED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "category" TEXT,
ADD COLUMN     "clusterId" TEXT,
ADD COLUMN     "dataSensitivity" TEXT,
ADD COLUMN     "environment" TEXT,
ADD COLUMN     "retestDueAt" TIMESTAMP(3),
ADD COLUMN     "slaPauseReason" TEXT,
ADD COLUMN     "slaPausedAt" TIMESTAMP(3),
ADD COLUMN     "sourceDomain" TEXT,
ADD COLUMN     "triageDueAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "FindingObservation" ADD COLUMN     "assetId" TEXT,
ADD COLUMN     "confidence" DOUBLE PRECISION,
ADD COLUMN     "evidenceRef" TEXT,
ADD COLUMN     "location" TEXT,
ADD COLUMN     "normalizedSeverity" TEXT,
ADD COLUMN     "rawArtifactRef" TEXT,
ADD COLUMN     "rawSeverity" TEXT,
ADD COLUMN     "ruleId" TEXT,
ADD COLUMN     "scannerInstanceId" TEXT,
ADD COLUMN     "targetRef" TEXT,
ADD COLUMN     "toolVersion" TEXT,
ADD COLUMN     "verificationState" TEXT;

-- CreateTable
CREATE TABLE "FindingCluster" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FindingCluster_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingCorrelation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "fromFindingId" TEXT NOT NULL,
    "toFindingId" TEXT NOT NULL,
    "relationship" TEXT NOT NULL,
    "rationale" TEXT,
    "createdBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingCorrelation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingOwnership" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "ownerType" TEXT NOT NULL,
    "ownerRef" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'MANUAL',
    "ruleId" TEXT,
    "assignedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FindingOwnership_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OwnershipRule" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "matchKind" TEXT NOT NULL,
    "matchValue" TEXT NOT NULL,
    "ownerType" TEXT NOT NULL,
    "ownerRef" TEXT NOT NULL,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OwnershipRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VmSlaPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "rules" JSONB NOT NULL,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VmSlaPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskException" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "requestedBy" TEXT NOT NULL,
    "approvedBy" TEXT,
    "reason" TEXT NOT NULL,
    "scope" JSONB,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskException_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ExternalFindingReference" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "findingId" TEXT,
    "externalSystem" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "externalUrl" TEXT,
    "externalStatus" TEXT,
    "externalSeverity" TEXT,
    "syncVersion" INTEGER NOT NULL DEFAULT 1,
    "lastSyncedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ExternalFindingReference_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IntegrationConflict" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "findingId" TEXT,
    "externalReferenceId" TEXT,
    "field" TEXT NOT NULL,
    "localValue" TEXT,
    "externalValue" TEXT,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "resolvedBy" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IntegrationConflict_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IntegrationJob" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "mode" TEXT,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "summary" JSONB NOT NULL DEFAULT '{}',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "IntegrationJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReportTemplate" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "organizationName" TEXT,
    "logoRef" TEXT,
    "sections" JSONB NOT NULL DEFAULT '[]',
    "severityDefinitions" JSONB NOT NULL DEFAULT '{}',
    "footer" TEXT,
    "classification" TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    "customBlocks" JSONB NOT NULL DEFAULT '[]',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ReportTemplate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityReport" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "scope" JSONB NOT NULL DEFAULT '{}',
    "periodStart" TIMESTAMP(3),
    "periodEnd" TIMESTAMP(3),
    "generatedBy" TEXT NOT NULL,
    "templateId" TEXT,
    "version" TEXT NOT NULL DEFAULT 'v1',
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "approvalStatus" TEXT NOT NULL DEFAULT 'DRAFT',
    "classification" TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    "changeNotes" TEXT,
    "approvedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityReport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReportSnapshot" (
    "id" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "data" JSONB NOT NULL,
    "contentHash" TEXT NOT NULL,
    "findingCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReportSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReportExport" (
    "id" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "format" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'READY',
    "storageLocation" TEXT,
    "checksum" TEXT,
    "sizeBytes" INTEGER,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReportExport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReportSchedule" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "reportType" TEXT NOT NULL,
    "templateId" TEXT,
    "cronExpression" TEXT NOT NULL,
    "recipients" JSONB NOT NULL DEFAULT '[]',
    "formats" JSONB NOT NULL DEFAULT '[]',
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ReportSchedule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "metrics" JSONB NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RiskSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VmNotificationEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "findingId" TEXT,
    "payload" JSONB NOT NULL DEFAULT '{}',
    "processedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VmNotificationEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VmTag" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'FINDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VmTag_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "FindingCluster_workspaceId_idx" ON "FindingCluster"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "FindingCluster_workspaceId_key_key" ON "FindingCluster"("workspaceId", "key");

-- CreateIndex
CREATE INDEX "FindingCorrelation_workspaceId_idx" ON "FindingCorrelation"("workspaceId");

-- CreateIndex
CREATE INDEX "FindingCorrelation_fromFindingId_idx" ON "FindingCorrelation"("fromFindingId");

-- CreateIndex
CREATE INDEX "FindingCorrelation_toFindingId_idx" ON "FindingCorrelation"("toFindingId");

-- CreateIndex
CREATE UNIQUE INDEX "FindingCorrelation_fromFindingId_toFindingId_relationship_key" ON "FindingCorrelation"("fromFindingId", "toFindingId", "relationship");

-- CreateIndex
CREATE UNIQUE INDEX "FindingOwnership_findingId_key" ON "FindingOwnership"("findingId");

-- CreateIndex
CREATE INDEX "FindingOwnership_workspaceId_idx" ON "FindingOwnership"("workspaceId");

-- CreateIndex
CREATE INDEX "FindingOwnership_workspaceId_ownerRef_idx" ON "FindingOwnership"("workspaceId", "ownerRef");

-- CreateIndex
CREATE INDEX "OwnershipRule_workspaceId_enabled_idx" ON "OwnershipRule"("workspaceId", "enabled");

-- CreateIndex
CREATE INDEX "VmSlaPolicy_workspaceId_idx" ON "VmSlaPolicy"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "VmSlaPolicy_workspaceId_name_key" ON "VmSlaPolicy"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "RiskException_workspaceId_status_idx" ON "RiskException"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RiskException_findingId_idx" ON "RiskException"("findingId");

-- CreateIndex
CREATE INDEX "RiskException_expiresAt_idx" ON "RiskException"("expiresAt");

-- CreateIndex
CREATE INDEX "ExternalFindingReference_workspaceId_idx" ON "ExternalFindingReference"("workspaceId");

-- CreateIndex
CREATE INDEX "ExternalFindingReference_findingId_idx" ON "ExternalFindingReference"("findingId");

-- CreateIndex
CREATE UNIQUE INDEX "ExternalFindingReference_integrationId_externalId_key" ON "ExternalFindingReference"("integrationId", "externalId");

-- CreateIndex
CREATE INDEX "IntegrationConflict_workspaceId_status_idx" ON "IntegrationConflict"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "IntegrationConflict_integrationId_idx" ON "IntegrationConflict"("integrationId");

-- CreateIndex
CREATE INDEX "IntegrationJob_workspaceId_status_idx" ON "IntegrationJob"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "IntegrationJob_integrationId_idx" ON "IntegrationJob"("integrationId");

-- CreateIndex
CREATE INDEX "ReportTemplate_workspaceId_idx" ON "ReportTemplate"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "ReportTemplate_workspaceId_name_key" ON "ReportTemplate"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "SecurityReport_workspaceId_status_idx" ON "SecurityReport"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "SecurityReport_workspaceId_type_idx" ON "SecurityReport"("workspaceId", "type");

-- CreateIndex
CREATE UNIQUE INDEX "ReportSnapshot_reportId_key" ON "ReportSnapshot"("reportId");

-- CreateIndex
CREATE INDEX "ReportSnapshot_workspaceId_idx" ON "ReportSnapshot"("workspaceId");

-- CreateIndex
CREATE INDEX "ReportExport_reportId_idx" ON "ReportExport"("reportId");

-- CreateIndex
CREATE INDEX "ReportExport_workspaceId_idx" ON "ReportExport"("workspaceId");

-- CreateIndex
CREATE INDEX "ReportSchedule_workspaceId_enabled_idx" ON "ReportSchedule"("workspaceId", "enabled");

-- CreateIndex
CREATE INDEX "RiskSnapshot_workspaceId_capturedAt_idx" ON "RiskSnapshot"("workspaceId", "capturedAt");

-- CreateIndex
CREATE INDEX "VmNotificationEvent_workspaceId_type_idx" ON "VmNotificationEvent"("workspaceId", "type");

-- CreateIndex
CREATE INDEX "VmNotificationEvent_workspaceId_createdAt_idx" ON "VmNotificationEvent"("workspaceId", "createdAt");

-- CreateIndex
CREATE INDEX "VmTag_workspaceId_idx" ON "VmTag"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "VmTag_workspaceId_kind_name_key" ON "VmTag"("workspaceId", "kind", "name");

-- CreateIndex
CREATE INDEX "Finding_workspaceId_sourceDomain_idx" ON "Finding"("workspaceId", "sourceDomain");

-- CreateIndex
CREATE INDEX "Finding_workspaceId_category_idx" ON "Finding"("workspaceId", "category");

-- CreateIndex
CREATE INDEX "Finding_workspaceId_environment_idx" ON "Finding"("workspaceId", "environment");

-- CreateIndex
CREATE INDEX "Finding_clusterId_idx" ON "Finding"("clusterId");

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_clusterId_fkey" FOREIGN KEY ("clusterId") REFERENCES "FindingCluster"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingCorrelation" ADD CONSTRAINT "FindingCorrelation_fromFindingId_fkey" FOREIGN KEY ("fromFindingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingCorrelation" ADD CONSTRAINT "FindingCorrelation_toFindingId_fkey" FOREIGN KEY ("toFindingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingOwnership" ADD CONSTRAINT "FindingOwnership_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RiskException" ADD CONSTRAINT "RiskException_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ExternalFindingReference" ADD CONSTRAINT "ExternalFindingReference_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportSnapshot" ADD CONSTRAINT "ReportSnapshot_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "SecurityReport"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportExport" ADD CONSTRAINT "ReportExport_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "SecurityReport"("id") ON DELETE CASCADE ON UPDATE CASCADE;

