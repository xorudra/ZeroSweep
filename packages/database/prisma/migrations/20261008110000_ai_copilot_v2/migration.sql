-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'AI_RETRIEVAL_PERFORMED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_PLAN_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_PLAN_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_ACTION_APPROVAL_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_ACTION_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_ACTION_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_WORKFLOW_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_WORKFLOW_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_TOOL_CALLED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_FEEDBACK_RECEIVED';

-- AlterTable
ALTER TABLE "AiFeedback" ADD COLUMN     "correction" TEXT;

-- AlterTable
ALTER TABLE "AiModel" ADD COLUMN     "costClass" TEXT NOT NULL DEFAULT 'LOW',
ADD COLUMN     "embeddingSupport" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "latencyClass" TEXT NOT NULL DEFAULT 'STANDARD',
ADD COLUMN     "structuredOutputSupport" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "toolCallingSupport" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "AiWorkspacePolicy" ADD COLUMN     "allowExternalProviders" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "allowedModelIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "approvalPolicy" TEXT NOT NULL DEFAULT 'SOD_RESTRICTED',
ADD COLUMN     "dataResidencyRegion" TEXT,
ADD COLUMN     "retentionEvaluationDays" INTEGER NOT NULL DEFAULT 365,
ADD COLUMN     "retentionTraceDays" INTEGER NOT NULL DEFAULT 90;

-- CreateTable
CREATE TABLE "AiSecurityWorkflow" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "requestedBy" TEXT NOT NULL,
    "taskType" TEXT NOT NULL,
    "objective" TEXT NOT NULL,
    "mode" TEXT NOT NULL DEFAULT 'READ_ONLY',
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "plan" JSONB NOT NULL DEFAULT '{}',
    "validation" JSONB NOT NULL DEFAULT '{}',
    "authorizationSnapshotHash" TEXT,
    "maxSteps" INTEGER NOT NULL DEFAULT 8,
    "maxTokens" INTEGER NOT NULL DEFAULT 12000,
    "result" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "AiSecurityWorkflow_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiActionApproval" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "workflowId" TEXT NOT NULL,
    "stepId" TEXT,
    "requestedBy" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "riskClass" TEXT NOT NULL DEFAULT 'LOW',
    "scope" JSONB NOT NULL DEFAULT '{}',
    "decision" TEXT NOT NULL DEFAULT 'PENDING',
    "approvedBy" TEXT,
    "approvedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiActionApproval_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiSecurityTrace" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "requestLogId" TEXT,
    "workflowId" TEXT,
    "taskType" TEXT NOT NULL,
    "requestMetadata" JSONB NOT NULL DEFAULT '{}',
    "retrievalRefs" JSONB NOT NULL DEFAULT '[]',
    "modelMetadata" JSONB NOT NULL DEFAULT '{}',
    "toolCalls" JSONB NOT NULL DEFAULT '[]',
    "policyDecisions" JSONB NOT NULL DEFAULT '[]',
    "validationResults" JSONB NOT NULL DEFAULT '[]',
    "timings" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiSecurityTrace_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiCopilotMemory" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'PREFERENCE',
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiCopilotMemory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiReportDraft" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "reportId" TEXT,
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "reviewStatus" TEXT NOT NULL DEFAULT 'UNREVIEWED',
    "reviewerId" TEXT,
    "factCheck" JSONB NOT NULL DEFAULT '{}',
    "requestLogId" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiReportDraft_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AiSecurityWorkflow_workspaceId_status_idx" ON "AiSecurityWorkflow"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AiSecurityWorkflow_workspaceId_requestedBy_idx" ON "AiSecurityWorkflow"("workspaceId", "requestedBy");

-- CreateIndex
CREATE INDEX "AiActionApproval_workspaceId_decision_idx" ON "AiActionApproval"("workspaceId", "decision");

-- CreateIndex
CREATE INDEX "AiActionApproval_workflowId_idx" ON "AiActionApproval"("workflowId");

-- CreateIndex
CREATE INDEX "AiSecurityTrace_workspaceId_createdAt_idx" ON "AiSecurityTrace"("workspaceId", "createdAt");

-- CreateIndex
CREATE INDEX "AiSecurityTrace_workspaceId_taskType_idx" ON "AiSecurityTrace"("workspaceId", "taskType");

-- CreateIndex
CREATE INDEX "AiCopilotMemory_workspaceId_userId_idx" ON "AiCopilotMemory"("workspaceId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "AiCopilotMemory_workspaceId_userId_key_key" ON "AiCopilotMemory"("workspaceId", "userId", "key");

-- CreateIndex
CREATE INDEX "AiReportDraft_workspaceId_status_idx" ON "AiReportDraft"("workspaceId", "status");

-- AddForeignKey
ALTER TABLE "AiActionApproval" ADD CONSTRAINT "AiActionApproval_workflowId_fkey" FOREIGN KEY ("workflowId") REFERENCES "AiSecurityWorkflow"("id") ON DELETE CASCADE ON UPDATE CASCADE;

