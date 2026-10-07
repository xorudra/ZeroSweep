-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_CORRELATED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_REVIEWED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_CONFIRMED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_FALSE_POSITIVE';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_RECALCULATED';

-- AlterTable
ALTER TABLE "Asset" ADD COLUMN     "criticality" TEXT NOT NULL DEFAULT 'UNSPECIFIED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "confidenceBand" TEXT,
ADD COLUMN     "reviewNotes" TEXT,
ADD COLUMN     "reviewStatus" TEXT,
ADD COLUMN     "reviewedAt" TIMESTAMP(3),
ADD COLUMN     "reviewedBy" TEXT,
ADD COLUMN     "riskBand" TEXT,
ADD COLUMN     "riskExplanation" JSONB,
ADD COLUMN     "riskScore" DOUBLE PRECISION,
ADD COLUMN     "sources" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "vulnClass" TEXT;

-- AlterTable
ALTER TABLE "FindingEvidence" ADD COLUMN     "matchedAt" TEXT,
ADD COLUMN     "metadata" JSONB;

-- CreateTable
CREATE TABLE "FindingHistory" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "actorId" TEXT,
    "notes" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingHistory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "FindingHistory_findingId_idx" ON "FindingHistory"("findingId");

-- CreateIndex
CREATE INDEX "FindingHistory_workspaceId_idx" ON "FindingHistory"("workspaceId");

-- CreateIndex
CREATE INDEX "Finding_assetId_idx" ON "Finding"("assetId");

-- CreateIndex
CREATE INDEX "Finding_status_idx" ON "Finding"("status");

-- CreateIndex
CREATE INDEX "Finding_cve_idx" ON "Finding"("cve");

-- CreateIndex
CREATE INDEX "Finding_cwe_idx" ON "Finding"("cwe");

-- CreateIndex
CREATE INDEX "Finding_verificationStatus_idx" ON "Finding"("verificationStatus");

-- CreateIndex
CREATE INDEX "Finding_createdAt_idx" ON "Finding"("createdAt");

-- AddForeignKey
ALTER TABLE "FindingHistory" ADD CONSTRAINT "FindingHistory_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

