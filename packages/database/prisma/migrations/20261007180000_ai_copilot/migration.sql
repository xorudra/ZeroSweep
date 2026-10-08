-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'AI_REQUEST_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_RESPONSE_GENERATED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_CONTEXT_REDACTED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_POLICY_BLOCKED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_ACTION_PROPOSED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_FEEDBACK_SUBMITTED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_PROVIDER_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_MODEL_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'AI_KNOWLEDGE_DOCUMENT_ADDED';

-- CreateTable
CREATE TABLE "AiProviderConfig" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "providerType" TEXT NOT NULL,
    "baseUrl" TEXT,
    "credentialRef" TEXT,
    "isExternal" BOOLEAN NOT NULL DEFAULT true,
    "region" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "approvedClassifications" TEXT[] DEFAULT ARRAY['PUBLIC', 'INTERNAL']::TEXT[],
    "sourceCodeAllowance" TEXT NOT NULL DEFAULT 'REDACTED',
    "retentionPolicy" TEXT,
    "healthStatus" TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
    "lastHealthCheckAt" TIMESTAMP(3),
    "lastSuccessfulAt" TIMESTAMP(3),
    "lastLatencyMs" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiProviderConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiModel" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "modelName" TEXT NOT NULL,
    "capabilities" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "contextLimit" INTEGER NOT NULL DEFAULT 8192,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "allowedTasks" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "isFallbackFor" TEXT,
    "costMetadata" JSONB,
    "healthStatus" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "lastCheckedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiModel_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiWorkspacePolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "sourceCodeAccess" TEXT NOT NULL DEFAULT 'REDACTED',
    "rawEvidenceAccess" TEXT NOT NULL DEFAULT 'SANITIZED_ONLY',
    "enabledTasks" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "chatRetentionDays" INTEGER NOT NULL DEFAULT 30,
    "primaryModelId" TEXT,
    "fallbackModelId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiWorkspacePolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiUsageBudget" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "dailyTokenLimit" INTEGER NOT NULL DEFAULT 200000,
    "monthlyTokenLimit" INTEGER NOT NULL DEFAULT 4000000,
    "perTaskTokenLimit" INTEGER NOT NULL DEFAULT 16000,
    "maxRetrievalRecords" INTEGER NOT NULL DEFAULT 25,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiUsageBudget_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiConversation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "contextType" TEXT NOT NULL DEFAULT 'WORKSPACE',
    "contextId" TEXT,
    "title" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiConversation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiMessage" (
    "id" TEXT NOT NULL,
    "conversationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "modelName" TEXT,
    "providerName" TEXT,
    "answerOrigin" TEXT,
    "confidence" TEXT,
    "citations" JSONB NOT NULL DEFAULT '[]',
    "tokenUsage" JSONB,
    "requestLogId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiMessage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiRequestLog" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "task" TEXT NOT NULL,
    "providerName" TEXT,
    "modelName" TEXT,
    "status" TEXT NOT NULL,
    "policyDecision" TEXT,
    "latencyMs" INTEGER,
    "promptTokens" INTEGER,
    "completionTokens" INTEGER,
    "redactionCount" INTEGER NOT NULL DEFAULT 0,
    "citationCount" INTEGER NOT NULL DEFAULT 0,
    "injectionFlags" INTEGER NOT NULL DEFAULT 0,
    "contextHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiRequestLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiCitation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "requestLogId" TEXT NOT NULL,
    "claim" TEXT NOT NULL,
    "sourceType" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "evidenceReference" TEXT,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiCitation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiSuggestedPatch" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "filePath" TEXT,
    "diff" TEXT NOT NULL,
    "modelName" TEXT,
    "citations" JSONB NOT NULL DEFAULT '[]',
    "confidence" TEXT,
    "status" TEXT NOT NULL DEFAULT 'PROPOSED',
    "reviewedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiSuggestedPatch_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiActionProposal" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "proposedByUserId" TEXT NOT NULL,
    "actionType" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "scope" JSONB NOT NULL DEFAULT '{}',
    "requiredPermission" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PROPOSED',
    "decidedBy" TEXT,
    "decidedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiActionProposal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiFeedback" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "messageId" TEXT,
    "requestLogId" TEXT,
    "task" TEXT,
    "rating" TEXT NOT NULL,
    "comment" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiFeedback_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KnowledgeDocument" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "classification" TEXT NOT NULL DEFAULT 'INTERNAL',
    "version" TEXT NOT NULL DEFAULT '1',
    "contentHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "content" TEXT NOT NULL,
    "injectionFlags" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KnowledgeDocument_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiEmbedding" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "sourceType" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "classification" TEXT NOT NULL DEFAULT 'INTERNAL',
    "vector" JSONB NOT NULL,
    "contentHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiEmbedding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiEvaluationRun" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "suite" TEXT NOT NULL DEFAULT 'GOLDEN',
    "passed" INTEGER NOT NULL,
    "failed" INTEGER NOT NULL,
    "results" JSONB NOT NULL DEFAULT '[]',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiEvaluationRun_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AiProviderConfig_workspaceId_idx" ON "AiProviderConfig"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "AiProviderConfig_workspaceId_name_key" ON "AiProviderConfig"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "AiModel_workspaceId_idx" ON "AiModel"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "AiModel_workspaceId_providerId_modelName_key" ON "AiModel"("workspaceId", "providerId", "modelName");

-- CreateIndex
CREATE UNIQUE INDEX "AiWorkspacePolicy_workspaceId_key" ON "AiWorkspacePolicy"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "AiUsageBudget_workspaceId_key" ON "AiUsageBudget"("workspaceId");

-- CreateIndex
CREATE INDEX "AiConversation_workspaceId_userId_idx" ON "AiConversation"("workspaceId", "userId");

-- CreateIndex
CREATE INDEX "AiConversation_workspaceId_contextType_contextId_idx" ON "AiConversation"("workspaceId", "contextType", "contextId");

-- CreateIndex
CREATE INDEX "AiMessage_conversationId_createdAt_idx" ON "AiMessage"("conversationId", "createdAt");

-- CreateIndex
CREATE INDEX "AiMessage_workspaceId_idx" ON "AiMessage"("workspaceId");

-- CreateIndex
CREATE INDEX "AiRequestLog_workspaceId_createdAt_idx" ON "AiRequestLog"("workspaceId", "createdAt");

-- CreateIndex
CREATE INDEX "AiRequestLog_workspaceId_task_idx" ON "AiRequestLog"("workspaceId", "task");

-- CreateIndex
CREATE INDEX "AiCitation_workspaceId_requestLogId_idx" ON "AiCitation"("workspaceId", "requestLogId");

-- CreateIndex
CREATE INDEX "AiSuggestedPatch_workspaceId_findingId_idx" ON "AiSuggestedPatch"("workspaceId", "findingId");

-- CreateIndex
CREATE INDEX "AiSuggestedPatch_workspaceId_status_idx" ON "AiSuggestedPatch"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AiActionProposal_workspaceId_status_idx" ON "AiActionProposal"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AiFeedback_workspaceId_rating_idx" ON "AiFeedback"("workspaceId", "rating");

-- CreateIndex
CREATE INDEX "AiFeedback_workspaceId_task_idx" ON "AiFeedback"("workspaceId", "task");

-- CreateIndex
CREATE INDEX "KnowledgeDocument_workspaceId_status_idx" ON "KnowledgeDocument"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AiEmbedding_workspaceId_sourceType_idx" ON "AiEmbedding"("workspaceId", "sourceType");

-- CreateIndex
CREATE UNIQUE INDEX "AiEmbedding_workspaceId_sourceType_sourceId_key" ON "AiEmbedding"("workspaceId", "sourceType", "sourceId");

-- CreateIndex
CREATE INDEX "AiEvaluationRun_workspaceId_createdAt_idx" ON "AiEvaluationRun"("workspaceId", "createdAt");

-- AddForeignKey
ALTER TABLE "AiModel" ADD CONSTRAINT "AiModel_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "AiProviderConfig"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AiMessage" ADD CONSTRAINT "AiMessage_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "AiConversation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AiCitation" ADD CONSTRAINT "AiCitation_requestLogId_fkey" FOREIGN KEY ("requestLogId") REFERENCES "AiRequestLog"("id") ON DELETE CASCADE ON UPDATE CASCADE;

