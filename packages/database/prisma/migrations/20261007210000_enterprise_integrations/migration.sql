-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "IntegrationType" ADD VALUE 'GITHUB';
ALTER TYPE "IntegrationType" ADD VALUE 'GITLAB';
ALTER TYPE "IntegrationType" ADD VALUE 'BITBUCKET';
ALTER TYPE "IntegrationType" ADD VALUE 'JIRA';
ALTER TYPE "IntegrationType" ADD VALUE 'SLACK';
ALTER TYPE "IntegrationType" ADD VALUE 'MICROSOFT_TEAMS';
ALTER TYPE "IntegrationType" ADD VALUE 'SIEM';
ALTER TYPE "IntegrationType" ADD VALUE 'GENERIC_WEBHOOK';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'INTEGRATION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'INTEGRATION_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'INTEGRATION_DELETED';
ALTER TYPE "AuditAction" ADD VALUE 'INTEGRATION_TESTED';
ALTER TYPE "AuditAction" ADD VALUE 'INTEGRATION_AUTH_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'REPOSITORY_CONNECTED';
ALTER TYPE "AuditAction" ADD VALUE 'REPOSITORY_SYNCED';
ALTER TYPE "AuditAction" ADD VALUE 'SOURCE_WEBHOOK_RECEIVED';
ALTER TYPE "AuditAction" ADD VALUE 'PR_SECURITY_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'PR_SECURITY_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'QUALITY_GATE_PASSED';
ALTER TYPE "AuditAction" ADD VALUE 'QUALITY_GATE_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_TICKET_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_TICKET_SYNCED';
ALTER TYPE "AuditAction" ADD VALUE 'SIEM_EVENT_EXPORTED';
ALTER TYPE "AuditAction" ADD VALUE 'WEBHOOK_DELIVERED';
ALTER TYPE "AuditAction" ADD VALUE 'WEBHOOK_DELIVERY_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'PIPELINE_SCAN_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'TICKET_SYNC_CONFLICT_DETECTED';

-- AlterTable
ALTER TABLE "Integration" ADD COLUMN     "capabilities" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "configuration" JSONB,
ADD COLUMN     "createdBy" TEXT,
ADD COLUMN     "credentialType" TEXT,
ADD COLUMN     "healthDetail" JSONB,
ADD COLUMN     "lastErrorCategory" TEXT,
ADD COLUMN     "lastHealthCheckAt" TIMESTAMP(3),
ADD COLUMN     "lastSyncAt" TIMESTAMP(3),
ADD COLUMN     "organizationId" TEXT,
ADD COLUMN     "secretReference" TEXT,
ADD COLUMN     "secretRotatedAt" TIMESTAMP(3),
ADD COLUMN     "status" TEXT NOT NULL DEFAULT 'PENDING';

-- CreateTable
CREATE TABLE "RepositoryIntegrationLink" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "sourceRepositoryId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "externalRepositoryId" TEXT NOT NULL,
    "externalRepositoryRef" TEXT NOT NULL,
    "installationId" TEXT,
    "defaultBranch" TEXT,
    "visibility" TEXT NOT NULL DEFAULT 'PRIVATE',
    "archived" BOOLEAN NOT NULL DEFAULT false,
    "languages" JSONB NOT NULL DEFAULT '[]',
    "lastSyncedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RepositoryIntegrationLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RepositorySecurityPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "sourceRepositoryId" TEXT NOT NULL,
    "scanOnPush" BOOLEAN NOT NULL DEFAULT false,
    "scanOnPullRequest" BOOLEAN NOT NULL DEFAULT false,
    "scanDefaultBranch" BOOLEAN NOT NULL DEFAULT false,
    "sastEnabled" BOOLEAN NOT NULL DEFAULT true,
    "scaEnabled" BOOLEAN NOT NULL DEFAULT true,
    "secretScanEnabled" BOOLEAN NOT NULL DEFAULT true,
    "sbomEnabled" BOOLEAN NOT NULL DEFAULT true,
    "containerScanEnabled" BOOLEAN NOT NULL DEFAULT false,
    "gatePolicyId" TEXT,
    "prGatePreset" TEXT,
    "autoRetest" BOOLEAN NOT NULL DEFAULT false,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RepositorySecurityPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PullRequestSecurityAssessment" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "prNumber" INTEGER NOT NULL,
    "title" TEXT NOT NULL,
    "baseBranch" TEXT,
    "headBranch" TEXT,
    "baseCommit" TEXT,
    "headCommit" TEXT NOT NULL,
    "scanId" TEXT,
    "scanStatus" TEXT NOT NULL DEFAULT 'PENDING',
    "blockReason" TEXT,
    "gateResult" TEXT,
    "gateEvaluationId" TEXT,
    "newFindings" JSONB NOT NULL DEFAULT '[]',
    "resolvedFindings" JSONB NOT NULL DEFAULT '[]',
    "regressedFindings" JSONB NOT NULL DEFAULT '[]',
    "checkPublished" TEXT NOT NULL DEFAULT 'NOT_ATTEMPTED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PullRequestSecurityAssessment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityGatePolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "repositorySelector" JSONB NOT NULL DEFAULT '{}',
    "branchSelector" JSONB NOT NULL DEFAULT '{}',
    "rules" JSONB NOT NULL DEFAULT '[]',
    "scannerFailureBehavior" TEXT NOT NULL DEFAULT 'FAIL_CLOSED',
    "version" INTEGER NOT NULL DEFAULT 1,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityGatePolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityGateEvaluation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "policyId" TEXT,
    "policyVersion" INTEGER,
    "context" TEXT NOT NULL,
    "pullRequestAssessmentId" TEXT,
    "pipelineRunId" TEXT,
    "scanId" TEXT,
    "result" TEXT NOT NULL,
    "ruleResults" JSONB NOT NULL DEFAULT '[]',
    "summary" JSONB NOT NULL DEFAULT '{}',
    "evaluatedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityGateEvaluation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityBaseline" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "snapshotId" TEXT,
    "scanId" TEXT,
    "fingerprints" JSONB NOT NULL DEFAULT '[]',
    "findingCount" INTEGER NOT NULL DEFAULT 0,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityBaseline_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityPipelineRun" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "integrationId" TEXT,
    "provider" TEXT NOT NULL,
    "repositoryId" TEXT,
    "externalRepositoryId" TEXT,
    "commitSha" TEXT NOT NULL,
    "branch" TEXT,
    "prNumber" INTEGER,
    "externalPipelineId" TEXT NOT NULL,
    "scanIds" JSONB NOT NULL DEFAULT '[]',
    "gateResult" TEXT,
    "gateEvaluationId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'REQUESTED',
    "blockReason" TEXT,
    "requestedByKind" TEXT NOT NULL,
    "requestedById" TEXT NOT NULL,
    "summary" JSONB NOT NULL DEFAULT '{}',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "SecurityPipelineRun_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "JiraProjectMapping" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "findingType" TEXT,
    "team" TEXT,
    "assetGroup" TEXT,
    "projectKey" TEXT NOT NULL,
    "issueType" TEXT NOT NULL DEFAULT 'Task',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "JiraProjectMapping_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationTicket" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "externalId" TEXT,
    "externalKey" TEXT,
    "externalUrl" TEXT,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "externalStatus" TEXT,
    "assigneeReference" TEXT,
    "syncState" TEXT NOT NULL DEFAULT 'IN_SYNC',
    "lastSyncedStatus" TEXT,
    "lastSyncedAssignee" TEXT,
    "createdBy" TEXT NOT NULL,
    "lastSyncedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationTicket_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TicketSyncConflict" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "ticketId" TEXT NOT NULL,
    "findingId" TEXT,
    "field" TEXT NOT NULL,
    "localValue" TEXT,
    "externalValue" TEXT,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "resolvedBy" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TicketSyncConflict_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebhookSubscription" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "endpoint" TEXT NOT NULL,
    "events" JSONB NOT NULL DEFAULT '[]',
    "secretReference" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WebhookSubscription_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityEventOutbox" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "schemaVersion" TEXT NOT NULL DEFAULT '1.0',
    "payload" JSONB NOT NULL DEFAULT '{}',
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3),
    "lastErrorCategory" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deliveredAt" TIMESTAMP(3),

    CONSTRAINT "SecurityEventOutbox_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IntegrationDelivery" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "outboxId" TEXT,
    "eventId" TEXT NOT NULL,
    "integrationId" TEXT,
    "subscriptionId" TEXT,
    "destinationKind" TEXT NOT NULL,
    "attempt" INTEGER NOT NULL DEFAULT 1,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "responseMetadata" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "IntegrationDelivery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "InboundIntegrationEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT,
    "integrationId" TEXT,
    "provider" TEXT NOT NULL,
    "deliveryId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "signatureStatus" TEXT NOT NULL,
    "processingStatus" TEXT NOT NULL DEFAULT 'RECEIVED',
    "detail" TEXT,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "InboundIntegrationEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IntegrationSyncCheckpoint" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "integrationId" TEXT NOT NULL,
    "resourceKind" TEXT NOT NULL,
    "cursor" TEXT,
    "lastSyncedAt" TIMESTAMP(3),
    "lastSuccessAt" TIMESTAMP(3),
    "lastErrorCategory" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IntegrationSyncCheckpoint_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "RepositoryIntegrationLink_workspaceId_idx" ON "RepositoryIntegrationLink"("workspaceId");

-- CreateIndex
CREATE INDEX "RepositoryIntegrationLink_integrationId_idx" ON "RepositoryIntegrationLink"("integrationId");

-- CreateIndex
CREATE UNIQUE INDEX "RepositoryIntegrationLink_integrationId_externalRepositoryI_key" ON "RepositoryIntegrationLink"("integrationId", "externalRepositoryId");

-- CreateIndex
CREATE UNIQUE INDEX "RepositoryIntegrationLink_workspaceId_sourceRepositoryId_key" ON "RepositoryIntegrationLink"("workspaceId", "sourceRepositoryId");

-- CreateIndex
CREATE UNIQUE INDEX "RepositorySecurityPolicy_sourceRepositoryId_key" ON "RepositorySecurityPolicy"("sourceRepositoryId");

-- CreateIndex
CREATE INDEX "RepositorySecurityPolicy_workspaceId_idx" ON "RepositorySecurityPolicy"("workspaceId");

-- CreateIndex
CREATE INDEX "PullRequestSecurityAssessment_workspaceId_repositoryId_idx" ON "PullRequestSecurityAssessment"("workspaceId", "repositoryId");

-- CreateIndex
CREATE INDEX "PullRequestSecurityAssessment_scanId_idx" ON "PullRequestSecurityAssessment"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "PullRequestSecurityAssessment_workspaceId_repositoryId_prNu_key" ON "PullRequestSecurityAssessment"("workspaceId", "repositoryId", "prNumber", "headCommit");

-- CreateIndex
CREATE INDEX "SecurityGatePolicy_workspaceId_idx" ON "SecurityGatePolicy"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityGatePolicy_workspaceId_name_key" ON "SecurityGatePolicy"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "SecurityGateEvaluation_workspaceId_context_idx" ON "SecurityGateEvaluation"("workspaceId", "context");

-- CreateIndex
CREATE INDEX "SecurityGateEvaluation_pullRequestAssessmentId_idx" ON "SecurityGateEvaluation"("pullRequestAssessmentId");

-- CreateIndex
CREATE INDEX "SecurityGateEvaluation_pipelineRunId_idx" ON "SecurityGateEvaluation"("pipelineRunId");

-- CreateIndex
CREATE INDEX "SecurityBaseline_workspaceId_repositoryId_idx" ON "SecurityBaseline"("workspaceId", "repositoryId");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityBaseline_repositoryId_commitSha_key" ON "SecurityBaseline"("repositoryId", "commitSha");

-- CreateIndex
CREATE INDEX "SecurityPipelineRun_workspaceId_repositoryId_idx" ON "SecurityPipelineRun"("workspaceId", "repositoryId");

-- CreateIndex
CREATE INDEX "SecurityPipelineRun_workspaceId_status_idx" ON "SecurityPipelineRun"("workspaceId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityPipelineRun_workspaceId_provider_externalPipelineId_key" ON "SecurityPipelineRun"("workspaceId", "provider", "externalPipelineId");

-- CreateIndex
CREATE INDEX "JiraProjectMapping_workspaceId_integrationId_idx" ON "JiraProjectMapping"("workspaceId", "integrationId");

-- CreateIndex
CREATE INDEX "RemediationTicket_workspaceId_findingId_idx" ON "RemediationTicket"("workspaceId", "findingId");

-- CreateIndex
CREATE INDEX "RemediationTicket_workspaceId_status_idx" ON "RemediationTicket"("workspaceId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "RemediationTicket_integrationId_findingId_key" ON "RemediationTicket"("integrationId", "findingId");

-- CreateIndex
CREATE INDEX "TicketSyncConflict_workspaceId_status_idx" ON "TicketSyncConflict"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "TicketSyncConflict_ticketId_idx" ON "TicketSyncConflict"("ticketId");

-- CreateIndex
CREATE INDEX "WebhookSubscription_workspaceId_enabled_idx" ON "WebhookSubscription"("workspaceId", "enabled");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityEventOutbox_eventId_key" ON "SecurityEventOutbox"("eventId");

-- CreateIndex
CREATE INDEX "SecurityEventOutbox_workspaceId_status_idx" ON "SecurityEventOutbox"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "SecurityEventOutbox_status_nextAttemptAt_idx" ON "SecurityEventOutbox"("status", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "IntegrationDelivery_workspaceId_status_idx" ON "IntegrationDelivery"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "IntegrationDelivery_eventId_idx" ON "IntegrationDelivery"("eventId");

-- CreateIndex
CREATE INDEX "IntegrationDelivery_integrationId_idx" ON "IntegrationDelivery"("integrationId");

-- CreateIndex
CREATE INDEX "InboundIntegrationEvent_workspaceId_provider_idx" ON "InboundIntegrationEvent"("workspaceId", "provider");

-- CreateIndex
CREATE INDEX "InboundIntegrationEvent_processingStatus_idx" ON "InboundIntegrationEvent"("processingStatus");

-- CreateIndex
CREATE UNIQUE INDEX "InboundIntegrationEvent_integrationId_deliveryId_key" ON "InboundIntegrationEvent"("integrationId", "deliveryId");

-- CreateIndex
CREATE INDEX "IntegrationSyncCheckpoint_workspaceId_idx" ON "IntegrationSyncCheckpoint"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "IntegrationSyncCheckpoint_integrationId_resourceKind_key" ON "IntegrationSyncCheckpoint"("integrationId", "resourceKind");

-- CreateIndex
CREATE INDEX "Integration_organizationId_idx" ON "Integration"("organizationId");

