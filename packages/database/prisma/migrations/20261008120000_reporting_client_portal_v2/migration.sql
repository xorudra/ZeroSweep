-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'FINDING_STATE_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'FALSE_POSITIVE_SET';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_ACCEPTANCE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SECURITY_EXCEPTION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SLA_EXCEPTION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'FIX_CLAIMED';
ALTER TYPE "AuditAction" ADD VALUE 'VERIFICATION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'CLIENT_COMMENT_ADDED';
ALTER TYPE "AuditAction" ADD VALUE 'REPORT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'REPORT_REVIEWED';
ALTER TYPE "AuditAction" ADD VALUE 'REPORT_FINALIZED';
ALTER TYPE "AuditAction" ADD VALUE 'REPORT_SHARED';
ALTER TYPE "AuditAction" ADD VALUE 'CLIENT_FINDING_PUBLISHED';
ALTER TYPE "AuditAction" ADD VALUE 'CLIENT_FINDING_UNPUBLISHED';
ALTER TYPE "AuditAction" ADD VALUE 'CLIENT_PORTAL_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_SYNC_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_SYNC_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_SYNC_CONFLICT';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "Role" ADD VALUE 'CLIENT_VIEWER';
ALTER TYPE "Role" ADD VALUE 'CLIENT_REMEDIATOR';
ALTER TYPE "Role" ADD VALUE 'CLIENT_MANAGER';

-- DropIndex
DROP INDEX "ReportTemplate_workspaceId_name_key";

-- AlterTable
ALTER TABLE "ExternalFindingReference" ADD COLUMN     "contentHash" TEXT,
ADD COLUMN     "externalProject" TEXT,
ADD COLUMN     "externalWorkspace" TEXT,
ADD COLUMN     "origin" TEXT NOT NULL DEFAULT 'EXTERNAL';

-- AlterTable
ALTER TABLE "FindingComment" ADD COLUMN     "mentions" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "visibility" TEXT NOT NULL DEFAULT 'INTERNAL';

-- AlterTable
ALTER TABLE "FindingEvidence" ADD COLUMN     "visibility" TEXT NOT NULL DEFAULT 'INTERNAL';

-- AlterTable
ALTER TABLE "ReportTemplate" ADD COLUMN     "accentColor" TEXT,
ADD COLUMN     "clientLogoRef" TEXT,
ADD COLUMN     "clientName" TEXT,
ADD COLUMN     "confidentialityText" TEXT,
ADD COLUMN     "contactDetails" JSONB,
ADD COLUMN     "status" TEXT NOT NULL DEFAULT 'PUBLISHED',
ADD COLUMN     "version" INTEGER NOT NULL DEFAULT 1;

-- AlterTable
ALTER TABLE "SecurityReport" ADD COLUMN     "clientOrganizationId" TEXT,
ADD COLUMN     "engagementId" TEXT,
ADD COLUMN     "finalizedAt" TIMESTAMP(3),
ADD COLUMN     "requireSeparateApprover" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "reviewedBy" TEXT,
ADD COLUMN     "watermark" TEXT;

-- CreateTable
CREATE TABLE "ReportVersion" (
    "id" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "snapshotId" TEXT,
    "document" JSONB NOT NULL,
    "contentHash" TEXT NOT NULL,
    "artifactHash" TEXT NOT NULL,
    "signatureMetadata" JSONB,
    "finalizedBy" TEXT NOT NULL,
    "finalizedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReportVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReportShareLink" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "reportVersionId" TEXT,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "maxDownloads" INTEGER,
    "downloadCount" INTEGER NOT NULL DEFAULT 0,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReportShareLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingTemplate" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "status" TEXT NOT NULL DEFAULT 'PUBLISHED',
    "title" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "impact" TEXT,
    "remediation" TEXT,
    "references" JSONB NOT NULL DEFAULT '[]',
    "cwe" TEXT,
    "owaspCategory" TEXT,
    "defaultSeverity" TEXT NOT NULL DEFAULT 'MEDIUM',
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FindingTemplate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityException" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "reason" TEXT NOT NULL,
    "businessJustification" TEXT,
    "requestedBy" TEXT NOT NULL,
    "approverId" TEXT,
    "startDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiryDate" TIMESTAMP(3),
    "reviewDate" TIMESTAMP(3),
    "compensatingControls" JSONB,
    "riskExceptionId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityException_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClientOrganization" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "contactName" TEXT,
    "contactEmail" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClientOrganization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClientEngagement" (
    "id" TEXT NOT NULL,
    "clientOrganizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assessmentId" TEXT,
    "name" TEXT NOT NULL,
    "startDate" TIMESTAMP(3),
    "endDate" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "clientContacts" JSONB NOT NULL DEFAULT '[]',
    "reportVisibility" TEXT NOT NULL DEFAULT 'FINALIZED_ONLY',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClientEngagement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClientPortalUser" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "clientOrganizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "portalRole" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ClientPortalUser_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClientFindingPublication" (
    "id" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "publishedBy" TEXT NOT NULL,
    "publishedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    "revokedBy" TEXT,

    CONSTRAINT "ClientFindingPublication_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClientNotification" (
    "id" TEXT NOT NULL,
    "clientOrganizationId" TEXT NOT NULL,
    "engagementId" TEXT,
    "type" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "findingId" TEXT,
    "reportId" TEXT,
    "readAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ClientNotification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VulnerabilityMetricsSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "metrics" JSONB NOT NULL,
    "capturedBy" TEXT,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VulnerabilityMetricsSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ReportVersion_workspaceId_idx" ON "ReportVersion"("workspaceId");

-- CreateIndex
CREATE INDEX "ReportVersion_reportId_idx" ON "ReportVersion"("reportId");

-- CreateIndex
CREATE UNIQUE INDEX "ReportVersion_reportId_version_key" ON "ReportVersion"("reportId", "version");

-- CreateIndex
CREATE UNIQUE INDEX "ReportShareLink_tokenHash_key" ON "ReportShareLink"("tokenHash");

-- CreateIndex
CREATE INDEX "ReportShareLink_workspaceId_idx" ON "ReportShareLink"("workspaceId");

-- CreateIndex
CREATE INDEX "ReportShareLink_reportId_idx" ON "ReportShareLink"("reportId");

-- CreateIndex
CREATE INDEX "FindingTemplate_workspaceId_idx" ON "FindingTemplate"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "FindingTemplate_workspaceId_name_version_key" ON "FindingTemplate"("workspaceId", "name", "version");

-- CreateIndex
CREATE INDEX "SecurityException_workspaceId_status_idx" ON "SecurityException"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "SecurityException_findingId_idx" ON "SecurityException"("findingId");

-- CreateIndex
CREATE INDEX "SecurityException_expiryDate_idx" ON "SecurityException"("expiryDate");

-- CreateIndex
CREATE INDEX "ClientOrganization_workspaceId_idx" ON "ClientOrganization"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "ClientOrganization_workspaceId_slug_key" ON "ClientOrganization"("workspaceId", "slug");

-- CreateIndex
CREATE INDEX "ClientEngagement_workspaceId_idx" ON "ClientEngagement"("workspaceId");

-- CreateIndex
CREATE INDEX "ClientEngagement_clientOrganizationId_idx" ON "ClientEngagement"("clientOrganizationId");

-- CreateIndex
CREATE UNIQUE INDEX "ClientPortalUser_userId_key" ON "ClientPortalUser"("userId");

-- CreateIndex
CREATE INDEX "ClientPortalUser_clientOrganizationId_idx" ON "ClientPortalUser"("clientOrganizationId");

-- CreateIndex
CREATE INDEX "ClientPortalUser_workspaceId_idx" ON "ClientPortalUser"("workspaceId");

-- CreateIndex
CREATE INDEX "ClientFindingPublication_workspaceId_idx" ON "ClientFindingPublication"("workspaceId");

-- CreateIndex
CREATE INDEX "ClientFindingPublication_findingId_idx" ON "ClientFindingPublication"("findingId");

-- CreateIndex
CREATE UNIQUE INDEX "ClientFindingPublication_engagementId_findingId_key" ON "ClientFindingPublication"("engagementId", "findingId");

-- CreateIndex
CREATE INDEX "ClientNotification_clientOrganizationId_createdAt_idx" ON "ClientNotification"("clientOrganizationId", "createdAt");

-- CreateIndex
CREATE INDEX "VulnerabilityMetricsSnapshot_workspaceId_capturedAt_idx" ON "VulnerabilityMetricsSnapshot"("workspaceId", "capturedAt");

-- CreateIndex
CREATE UNIQUE INDEX "ReportTemplate_workspaceId_name_version_key" ON "ReportTemplate"("workspaceId", "name", "version");

-- AddForeignKey
ALTER TABLE "ReportVersion" ADD CONSTRAINT "ReportVersion_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "SecurityReport"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportShareLink" ADD CONSTRAINT "ReportShareLink_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "SecurityReport"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClientEngagement" ADD CONSTRAINT "ClientEngagement_clientOrganizationId_fkey" FOREIGN KEY ("clientOrganizationId") REFERENCES "ClientOrganization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClientPortalUser" ADD CONSTRAINT "ClientPortalUser_clientOrganizationId_fkey" FOREIGN KEY ("clientOrganizationId") REFERENCES "ClientOrganization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClientFindingPublication" ADD CONSTRAINT "ClientFindingPublication_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "ClientEngagement"("id") ON DELETE CASCADE ON UPDATE CASCADE;

