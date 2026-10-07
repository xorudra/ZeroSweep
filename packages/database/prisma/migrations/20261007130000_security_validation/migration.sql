-- CreateEnum
CREATE TYPE "ValidationRequestStatus" AS ENUM ('REQUESTED', 'POLICY_REVIEW', 'APPROVAL_REQUIRED', 'APPROVED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'INCONCLUSIVE', 'BLOCKED', 'CANCELLED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "ValidationRiskClass" AS ENUM ('SAFE', 'LOW_IMPACT', 'REVIEW_REQUIRED', 'INTRUSIVE', 'PROHIBITED_AUTOMATION');

-- CreateEnum
CREATE TYPE "ValidationEvidenceType" AS ENUM ('HTTP_REQUEST', 'HTTP_RESPONSE', 'TLS_RESULT', 'SERVICE_RESULT', 'CONFIGURATION_RESULT', 'SCREENSHOT', 'LOG', 'SCANNER_RESULT', 'MANUAL_NOTE');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_POLICY_EVALUATED';
ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_CANCELLED';
ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_BLOCKED';
ALTER TYPE "AuditAction" ADD VALUE 'VALIDATION_EVIDENCE_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'MANUAL_VALIDATION_ADDED';
ALTER TYPE "AuditAction" ADD VALUE 'KILL_SWITCH_ACTIVATED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "lastValidatedAt" TIMESTAMP(3),
ADD COLUMN     "validationConfidence" TEXT;

-- CreateTable
CREATE TABLE "ValidationRequest" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "requestedBy" TEXT NOT NULL,
    "validatorSlug" TEXT NOT NULL,
    "validationType" TEXT NOT NULL,
    "toolSlug" TEXT,
    "riskClass" "ValidationRiskClass" NOT NULL,
    "reason" TEXT,
    "authorizationSnapshot" JSONB NOT NULL,
    "scopeSnapshot" JSONB NOT NULL,
    "plan" JSONB NOT NULL,
    "planHash" TEXT NOT NULL,
    "parameters" JSONB,
    "budget" JSONB NOT NULL,
    "status" "ValidationRequestStatus" NOT NULL DEFAULT 'REQUESTED',
    "policyDecision" TEXT,
    "policyReason" TEXT,
    "outcome" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'PRODUCTION',
    "idempotencyKey" TEXT,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ValidationRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ValidationApproval" (
    "id" TEXT NOT NULL,
    "requestId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "approverId" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "reason" TEXT,
    "planHash" TEXT NOT NULL,
    "approvedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ValidationApproval_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ValidationSession" (
    "id" TEXT NOT NULL,
    "requestId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "workerId" TEXT,
    "toolSlug" TEXT,
    "validatorSlug" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "startedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "budget" JSONB NOT NULL,
    "budgetConsumed" JSONB,
    "terminationReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ValidationSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ValidationEvidence" (
    "id" TEXT NOT NULL,
    "requestId" TEXT NOT NULL,
    "sessionId" TEXT,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT,
    "type" "ValidationEvidenceType" NOT NULL,
    "summary" TEXT NOT NULL,
    "content" JSONB,
    "checksum" TEXT NOT NULL,
    "sourceTool" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ValidationEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ManualValidationRecord" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "analystId" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "outcome" TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
    "evidence" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ManualValidationRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ValidationPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "productionPolicy" TEXT NOT NULL DEFAULT 'SAFE_ONLY',
    "defaultRiskLevel" TEXT NOT NULL DEFAULT 'SAFE',
    "separationOfDuties" BOOLEAN NOT NULL DEFAULT true,
    "allowIntrusiveInLab" BOOLEAN NOT NULL DEFAULT false,
    "allowedValidators" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "hardLimits" JSONB NOT NULL,
    "defaultBudget" JSONB NOT NULL,
    "defaultTimeoutSeconds" INTEGER NOT NULL DEFAULT 300,
    "approvalTtlMinutes" INTEGER NOT NULL DEFAULT 60,
    "evidenceRetentionDays" INTEGER NOT NULL DEFAULT 365,
    "callbackEnabled" BOOLEAN NOT NULL DEFAULT false,
    "updatedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ValidationPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ValidationKillSwitch" (
    "id" TEXT NOT NULL,
    "level" TEXT NOT NULL,
    "organizationId" TEXT,
    "workspaceId" TEXT,
    "scopeRef" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "reason" TEXT,
    "activatedBy" TEXT NOT NULL,
    "activatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "clearedBy" TEXT,
    "clearedAt" TIMESTAMP(3),

    CONSTRAINT "ValidationKillSwitch_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ValidationCallbackToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "requestId" TEXT,
    "sessionId" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ValidationCallbackToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ValidationCallbackEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "tokenId" TEXT NOT NULL,
    "sessionId" TEXT,
    "kind" TEXT NOT NULL DEFAULT 'HTTP',
    "sourceIp" TEXT,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ValidationCallbackEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ValidationRequest_workspaceId_idx" ON "ValidationRequest"("workspaceId");

-- CreateIndex
CREATE INDEX "ValidationRequest_findingId_idx" ON "ValidationRequest"("findingId");

-- CreateIndex
CREATE INDEX "ValidationRequest_targetId_idx" ON "ValidationRequest"("targetId");

-- CreateIndex
CREATE INDEX "ValidationRequest_status_idx" ON "ValidationRequest"("status");

-- CreateIndex
CREATE UNIQUE INDEX "ValidationRequest_workspaceId_idempotencyKey_key" ON "ValidationRequest"("workspaceId", "idempotencyKey");

-- CreateIndex
CREATE INDEX "ValidationApproval_requestId_idx" ON "ValidationApproval"("requestId");

-- CreateIndex
CREATE INDEX "ValidationApproval_workspaceId_idx" ON "ValidationApproval"("workspaceId");

-- CreateIndex
CREATE INDEX "ValidationSession_requestId_idx" ON "ValidationSession"("requestId");

-- CreateIndex
CREATE INDEX "ValidationSession_workspaceId_idx" ON "ValidationSession"("workspaceId");

-- CreateIndex
CREATE INDEX "ValidationSession_status_idx" ON "ValidationSession"("status");

-- CreateIndex
CREATE INDEX "ValidationEvidence_requestId_idx" ON "ValidationEvidence"("requestId");

-- CreateIndex
CREATE INDEX "ValidationEvidence_sessionId_idx" ON "ValidationEvidence"("sessionId");

-- CreateIndex
CREATE INDEX "ValidationEvidence_workspaceId_idx" ON "ValidationEvidence"("workspaceId");

-- CreateIndex
CREATE INDEX "ManualValidationRecord_findingId_idx" ON "ManualValidationRecord"("findingId");

-- CreateIndex
CREATE INDEX "ManualValidationRecord_workspaceId_idx" ON "ManualValidationRecord"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "ValidationPolicy_workspaceId_key" ON "ValidationPolicy"("workspaceId");

-- CreateIndex
CREATE INDEX "ValidationPolicy_workspaceId_idx" ON "ValidationPolicy"("workspaceId");

-- CreateIndex
CREATE INDEX "ValidationKillSwitch_level_active_idx" ON "ValidationKillSwitch"("level", "active");

-- CreateIndex
CREATE INDEX "ValidationKillSwitch_workspaceId_idx" ON "ValidationKillSwitch"("workspaceId");

-- CreateIndex
CREATE INDEX "ValidationKillSwitch_organizationId_idx" ON "ValidationKillSwitch"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "ValidationCallbackToken_tokenHash_key" ON "ValidationCallbackToken"("tokenHash");

-- CreateIndex
CREATE INDEX "ValidationCallbackToken_workspaceId_idx" ON "ValidationCallbackToken"("workspaceId");

-- CreateIndex
CREATE INDEX "ValidationCallbackToken_expiresAt_idx" ON "ValidationCallbackToken"("expiresAt");

-- CreateIndex
CREATE INDEX "ValidationCallbackEvent_workspaceId_idx" ON "ValidationCallbackEvent"("workspaceId");

-- CreateIndex
CREATE INDEX "ValidationCallbackEvent_tokenId_idx" ON "ValidationCallbackEvent"("tokenId");

-- AddForeignKey
ALTER TABLE "ValidationRequest" ADD CONSTRAINT "ValidationRequest_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ValidationApproval" ADD CONSTRAINT "ValidationApproval_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "ValidationRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ValidationSession" ADD CONSTRAINT "ValidationSession_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "ValidationRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ValidationEvidence" ADD CONSTRAINT "ValidationEvidence_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "ValidationRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ValidationEvidence" ADD CONSTRAINT "ValidationEvidence_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "ValidationSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ManualValidationRecord" ADD CONSTRAINT "ManualValidationRecord_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

