-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssessmentProfile" ADD VALUE 'NETWORK_DISCOVERY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'NETWORK_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'NETWORK_COMPREHENSIVE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'NETWORK_INTERNAL';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'TARGET_EXPANSION';
ALTER TYPE "ScanStageType" ADD VALUE 'HOST_DISCOVERY';
ALTER TYPE "ScanStageType" ADD VALUE 'SERVICE_DETECTION';
ALTER TYPE "ScanStageType" ADD VALUE 'SAFE_NETWORK_CHECKS';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_SCAN_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_SCOPE_VALIDATED';
ALTER TYPE "AuditAction" ADD VALUE 'HOST_DISCOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'PORT_DISCOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'SERVICE_IDENTIFIED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'PROTECTED_TARGET_BLOCKED';
ALTER TYPE "AuditAction" ADD VALUE 'INTERNAL_SCAN_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'RAW_PCAP_ACCESSED';

-- AlterTable
ALTER TABLE "Asset" ADD COLUMN     "network" TEXT,
ADD COLUMN     "osConfidence" DOUBLE PRECISION,
ADD COLUMN     "osHint" TEXT;

-- AlterTable
ALTER TABLE "Service" ADD COLUMN     "banner" TEXT,
ADD COLUMN     "confidence" DOUBLE PRECISION,
ADD COLUMN     "cpe" TEXT,
ADD COLUMN     "sources" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "state" TEXT NOT NULL DEFAULT 'OPEN',
ADD COLUMN     "tls" BOOLEAN;

-- AlterTable
ALTER TABLE "WorkerNode" ADD COLUMN     "workerType" TEXT NOT NULL DEFAULT 'GENERAL_WEB';

-- CreateTable
CREATE TABLE "PacketCaptureArtifact" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT,
    "assetId" TEXT,
    "toolExecutionId" TEXT,
    "format" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "storageKey" TEXT NOT NULL,
    "sha256" TEXT,
    "sizeBytes" INTEGER,
    "durationSeconds" INTEGER,
    "interfaceName" TEXT,
    "packetCount" INTEGER,
    "retentionUntil" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PacketCaptureArtifact_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkScanChunk" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "chunkId" TEXT NOT NULL,
    "rangeStart" TEXT NOT NULL,
    "rangeEnd" TEXT NOT NULL,
    "hostCount" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "workerId" TEXT,
    "attempt" INTEGER NOT NULL DEFAULT 0,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NetworkScanChunk_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PacketCaptureArtifact_workspaceId_idx" ON "PacketCaptureArtifact"("workspaceId");

-- CreateIndex
CREATE INDEX "PacketCaptureArtifact_scanId_idx" ON "PacketCaptureArtifact"("scanId");

-- CreateIndex
CREATE INDEX "NetworkScanChunk_scanId_status_idx" ON "NetworkScanChunk"("scanId", "status");

-- CreateIndex
CREATE INDEX "NetworkScanChunk_workspaceId_idx" ON "NetworkScanChunk"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "NetworkScanChunk_scanId_chunkId_key" ON "NetworkScanChunk"("scanId", "chunkId");

-- AddForeignKey
ALTER TABLE "PacketCaptureArtifact" ADD CONSTRAINT "PacketCaptureArtifact_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE SET NULL ON UPDATE CASCADE;

