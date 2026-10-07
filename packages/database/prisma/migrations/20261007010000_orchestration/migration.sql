-- CreateEnum
CREATE TYPE "WorkerStatus" AS ENUM ('ONLINE', 'BUSY', 'DEGRADED', 'OFFLINE', 'DRAINING');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStatus" ADD VALUE 'CREATED';
ALTER TYPE "ScanStatus" ADD VALUE 'PAUSING';
ALTER TYPE "ScanStatus" ADD VALUE 'CANCELLING';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageStatus" ADD VALUE 'PENDING';
ALTER TYPE "ScanStageStatus" ADD VALUE 'BLOCKED';
ALTER TYPE "ScanStageStatus" ADD VALUE 'READY';
ALTER TYPE "ScanStageStatus" ADD VALUE 'PARTIAL';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ToolExecutionStatus" ADD VALUE 'PARSING';
ALTER TYPE "ToolExecutionStatus" ADD VALUE 'NORMALIZING';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'SCAN_PLANNED';
ALTER TYPE "AuditAction" ADD VALUE 'SCAN_PAUSED';
ALTER TYPE "AuditAction" ADD VALUE 'SCAN_RESUMED';
ALTER TYPE "AuditAction" ADD VALUE 'SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'POLICY_DENIED';
ALTER TYPE "AuditAction" ADD VALUE 'SCOPE_VIOLATION';

-- AlterTable
ALTER TABLE "Asset" ADD COLUMN     "scopeStatus" TEXT NOT NULL DEFAULT 'IN_SCOPE';

-- AlterTable
ALTER TABLE "ScanStage" ADD COLUMN     "dependencies" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "weight" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "ToolExecution" ADD COLUMN     "attempt" INTEGER NOT NULL DEFAULT 1,
ADD COLUMN     "idempotencyKey" TEXT;

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "isMock" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "toolExecutionId" TEXT;

-- CreateTable
CREATE TABLE "ScanPlan" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "assessmentId" TEXT NOT NULL,
    "profile" "AssessmentProfile" NOT NULL,
    "planVersion" INTEGER NOT NULL DEFAULT 1,
    "plan" JSONB NOT NULL,
    "policySnapshot" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanPlan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanEvent" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "payload" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WorkerNode" (
    "id" TEXT NOT NULL,
    "workerId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "status" "WorkerStatus" NOT NULL DEFAULT 'ONLINE',
    "capabilities" JSONB NOT NULL,
    "activeJobs" INTEGER NOT NULL DEFAULT 0,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastHeartbeat" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WorkerNode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeadLetterJob" (
    "id" TEXT NOT NULL,
    "jobId" TEXT NOT NULL,
    "queue" TEXT NOT NULL,
    "scanId" TEXT,
    "stageId" TEXT,
    "executionId" TEXT,
    "errorCategory" TEXT NOT NULL,
    "errorMessage" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DeadLetterJob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ScanPlan_scanId_key" ON "ScanPlan"("scanId");

-- CreateIndex
CREATE INDEX "ScanPlan_assessmentId_idx" ON "ScanPlan"("assessmentId");

-- CreateIndex
CREATE INDEX "ScanEvent_scanId_createdAt_idx" ON "ScanEvent"("scanId", "createdAt");

-- CreateIndex
CREATE INDEX "ScanEvent_workspaceId_idx" ON "ScanEvent"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "WorkerNode_workerId_key" ON "WorkerNode"("workerId");

-- CreateIndex
CREATE INDEX "WorkerNode_status_idx" ON "WorkerNode"("status");

-- CreateIndex
CREATE INDEX "WorkerNode_lastHeartbeat_idx" ON "WorkerNode"("lastHeartbeat");

-- CreateIndex
CREATE INDEX "DeadLetterJob_queue_idx" ON "DeadLetterJob"("queue");

-- CreateIndex
CREATE INDEX "DeadLetterJob_scanId_idx" ON "DeadLetterJob"("scanId");

-- CreateIndex
CREATE INDEX "DeadLetterJob_createdAt_idx" ON "DeadLetterJob"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ToolExecution_idempotencyKey_key" ON "ToolExecution"("idempotencyKey");

-- AddForeignKey
ALTER TABLE "ScanPlan" ADD CONSTRAINT "ScanPlan_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanEvent" ADD CONSTRAINT "ScanEvent_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

