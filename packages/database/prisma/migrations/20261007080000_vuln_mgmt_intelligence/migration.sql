-- CreateEnum
CREATE TYPE "VmLifecycleStatus" AS ENUM ('NEW', 'TRIAGED', 'CONFIRMED', 'IN_PROGRESS', 'REMEDIATED', 'RETEST_PENDING', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_TRIAGED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_ASSIGNED';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_ACCEPTED';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_ACCEPTANCE_EXPIRED';
ALTER TYPE "AuditAction" ADD VALUE 'FALSE_POSITIVE_MARKED';
ALTER TYPE "AuditAction" ADD VALUE 'RETEST_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'RETEST_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_RESOLVED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_REOPENED';
ALTER TYPE "AuditAction" ADD VALUE 'SCANNER_REPORT_IMPORTED';
ALTER TYPE "AuditAction" ADD VALUE 'INTELLIGENCE_UPDATED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "assignedAt" TIMESTAMP(3),
ADD COLUMN     "assignedBy" TEXT,
ADD COLUMN     "assignedToId" TEXT,
ADD COLUMN     "assignedToTeam" TEXT,
ADD COLUMN     "cpe" TEXT,
ADD COLUMN     "detectionKind" TEXT NOT NULL DEFAULT 'DETECTED_VULNERABILITY',
ADD COLUMN     "dueAt" TIMESTAMP(3),
ADD COLUMN     "epssPercentile" DOUBLE PRECISION,
ADD COLUMN     "epssScore" DOUBLE PRECISION,
ADD COLUMN     "exploitRefExists" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "intelCvssScore" DOUBLE PRECISION,
ADD COLUMN     "intelSnapshot" JSONB,
ADD COLUMN     "kevListed" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "lifecycleStatus" "VmLifecycleStatus" NOT NULL DEFAULT 'NEW',
ADD COLUMN     "priority" TEXT,
ADD COLUMN     "recurrenceCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "reopenedAt" TIMESTAMP(3),
ADD COLUMN     "resolvedAt" TIMESTAMP(3),
ADD COLUMN     "riskAcceptanceExpiresAt" TIMESTAMP(3),
ADD COLUMN     "riskAcceptanceReason" TEXT,
ADD COLUMN     "riskAcceptedBy" TEXT,
ADD COLUMN     "riskCalcVersion" TEXT,
ADD COLUMN     "riskFactors" JSONB,
ADD COLUMN     "slaPolicyId" TEXT,
ADD COLUMN     "tags" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- AlterTable
ALTER TABLE "ScannerInstance" ADD COLUMN     "config" JSONB NOT NULL DEFAULT '{}';

-- CreateTable
CREATE TABLE "CveRecord" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "publishedAt" TIMESTAMP(3),
    "modifiedAt" TIMESTAMP(3),
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "cvssVersion" TEXT,
    "cweIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "references" JSONB NOT NULL DEFAULT '[]',
    "source" TEXT NOT NULL,
    "lastSyncedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CveRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CweRecord" (
    "id" TEXT NOT NULL,
    "cweId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" TEXT,
    "references" JSONB NOT NULL DEFAULT '[]',
    "source" TEXT NOT NULL DEFAULT 'CURATED',
    "lastSyncedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CweRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CpeRecord" (
    "id" TEXT NOT NULL,
    "canonical" TEXT NOT NULL,
    "part" TEXT NOT NULL,
    "vendor" TEXT NOT NULL,
    "product" TEXT NOT NULL,
    "version" TEXT,
    "cveIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "source" TEXT NOT NULL DEFAULT 'SCANNER',
    "lastSyncedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CpeRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EpssRecord" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "score" DOUBLE PRECISION NOT NULL,
    "percentile" DOUBLE PRECISION NOT NULL,
    "date" TIMESTAMP(3) NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'FIRST_EPSS',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EpssRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KevRecord" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "dateAdded" TIMESTAMP(3),
    "vendorProject" TEXT,
    "product" TEXT,
    "vulnerabilityName" TEXT,
    "requiredAction" TEXT,
    "dueDate" TIMESTAMP(3),
    "knownRansomwareUse" TEXT,
    "source" TEXT NOT NULL DEFAULT 'CISA_KEV',
    "lastSyncedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KevRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IntelligenceSyncState" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'NEVER_SYNCED',
    "lastAttemptAt" TIMESTAMP(3),
    "lastSuccessAt" TIMESTAMP(3),
    "checksum" TEXT,
    "recordCount" INTEGER NOT NULL DEFAULT 0,
    "detail" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IntelligenceSyncState_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ExploitReference" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "reference" TEXT NOT NULL,
    "platform" TEXT,
    "type" TEXT,
    "verifiedMetadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ExploitReference_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingObservation" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT,
    "sourceTool" TEXT NOT NULL,
    "sourceFingerprint" TEXT NOT NULL DEFAULT '',
    "severity" TEXT NOT NULL,
    "summary" TEXT,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingComment" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "authorId" TEXT NOT NULL,
    "text" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingComment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationSlaPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "rules" JSONB NOT NULL,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationSlaPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RetestRequest" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "requestedBy" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "sourceTool" TEXT NOT NULL,
    "checkReference" TEXT,
    "scanId" TEXT,
    "result" TEXT,
    "previousEvidence" JSONB,
    "newEvidence" JSONB,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RetestRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScannerReportImport" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanner" TEXT NOT NULL,
    "scanId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'PREVIEW',
    "fileName" TEXT,
    "checksum" TEXT NOT NULL,
    "summary" JSONB NOT NULL DEFAULT '{}',
    "warnings" JSONB NOT NULL DEFAULT '[]',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScannerReportImport_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "CveRecord_cveId_key" ON "CveRecord"("cveId");

-- CreateIndex
CREATE INDEX "CveRecord_cveId_idx" ON "CveRecord"("cveId");

-- CreateIndex
CREATE UNIQUE INDEX "CweRecord_cweId_key" ON "CweRecord"("cweId");

-- CreateIndex
CREATE UNIQUE INDEX "CpeRecord_canonical_key" ON "CpeRecord"("canonical");

-- CreateIndex
CREATE INDEX "CpeRecord_vendor_product_idx" ON "CpeRecord"("vendor", "product");

-- CreateIndex
CREATE INDEX "EpssRecord_cveId_idx" ON "EpssRecord"("cveId");

-- CreateIndex
CREATE UNIQUE INDEX "EpssRecord_cveId_date_key" ON "EpssRecord"("cveId", "date");

-- CreateIndex
CREATE UNIQUE INDEX "KevRecord_cveId_key" ON "KevRecord"("cveId");

-- CreateIndex
CREATE UNIQUE INDEX "IntelligenceSyncState_source_key" ON "IntelligenceSyncState"("source");

-- CreateIndex
CREATE INDEX "ExploitReference_findingId_idx" ON "ExploitReference"("findingId");

-- CreateIndex
CREATE UNIQUE INDEX "ExploitReference_findingId_source_externalId_key" ON "ExploitReference"("findingId", "source", "externalId");

-- CreateIndex
CREATE INDEX "FindingObservation_findingId_idx" ON "FindingObservation"("findingId");

-- CreateIndex
CREATE INDEX "FindingObservation_workspaceId_idx" ON "FindingObservation"("workspaceId");

-- CreateIndex
CREATE INDEX "FindingObservation_scanId_idx" ON "FindingObservation"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "FindingObservation_findingId_sourceTool_sourceFingerprint_key" ON "FindingObservation"("findingId", "sourceTool", "sourceFingerprint");

-- CreateIndex
CREATE INDEX "FindingComment_findingId_idx" ON "FindingComment"("findingId");

-- CreateIndex
CREATE INDEX "FindingComment_workspaceId_idx" ON "FindingComment"("workspaceId");

-- CreateIndex
CREATE INDEX "RemediationSlaPolicy_workspaceId_idx" ON "RemediationSlaPolicy"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "RemediationSlaPolicy_workspaceId_name_key" ON "RemediationSlaPolicy"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "RetestRequest_findingId_idx" ON "RetestRequest"("findingId");

-- CreateIndex
CREATE INDEX "RetestRequest_workspaceId_idx" ON "RetestRequest"("workspaceId");

-- CreateIndex
CREATE INDEX "RetestRequest_status_idx" ON "RetestRequest"("status");

-- CreateIndex
CREATE INDEX "ScannerReportImport_workspaceId_idx" ON "ScannerReportImport"("workspaceId");

-- CreateIndex
CREATE INDEX "ScannerReportImport_status_idx" ON "ScannerReportImport"("status");

-- CreateIndex
CREATE INDEX "Finding_workspaceId_lifecycleStatus_idx" ON "Finding"("workspaceId", "lifecycleStatus");

-- CreateIndex
CREATE INDEX "Finding_workspaceId_priority_idx" ON "Finding"("workspaceId", "priority");

-- CreateIndex
CREATE INDEX "Finding_assignedToId_idx" ON "Finding"("assignedToId");

-- CreateIndex
CREATE INDEX "Finding_dueAt_idx" ON "Finding"("dueAt");

-- CreateIndex
CREATE INDEX "Finding_kevListed_idx" ON "Finding"("kevListed");

-- CreateIndex
CREATE INDEX "Finding_firstSeen_idx" ON "Finding"("firstSeen");

-- CreateIndex
CREATE INDEX "Finding_lastSeen_idx" ON "Finding"("lastSeen");

-- AddForeignKey
ALTER TABLE "ExploitReference" ADD CONSTRAINT "ExploitReference_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingObservation" ADD CONSTRAINT "FindingObservation_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingComment" ADD CONSTRAINT "FindingComment_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RetestRequest" ADD CONSTRAINT "RetestRequest_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

