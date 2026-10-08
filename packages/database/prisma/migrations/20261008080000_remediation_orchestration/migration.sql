-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_CASE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_TRIAGED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_ASSIGNED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_REASSIGNED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_PLAN_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_SLA_ASSIGNED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_SLA_PAUSED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_SLA_BREACHED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_FIX_CLAIMED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_VERIFICATION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_VERIFICATION_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_VERIFICATION_PASSED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_VERIFICATION_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_VERIFICATION_INCONCLUSIVE';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_VERIFIED_FIXED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_CLOSED';
ALTER TYPE "AuditAction" ADD VALUE 'VULNERABILITY_REGRESSION_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_EXCEPTION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_EXCEPTION_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_EXCEPTION_EXPIRED';
ALTER TYPE "AuditAction" ADD VALUE 'REMEDIATION_CAMPAIGN_CREATED';

-- AlterTable
ALTER TABLE "RemediationSlaPolicy" ADD COLUMN     "active" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "conditions" JSONB,
ADD COLUMN     "escalation" JSONB,
ADD COLUMN     "requiredCleanObservations" INTEGER NOT NULL DEFAULT 1,
ADD COLUMN     "verificationRequired" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "version" INTEGER NOT NULL DEFAULT 1,
ADD COLUMN     "warningThresholds" JSONB;

-- CreateTable
CREATE TABLE "RemediationCase" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'NEW',
    "priority" TEXT,
    "ownerType" TEXT,
    "ownerId" TEXT,
    "teamId" TEXT,
    "ownershipConfidence" TEXT,
    "slaPolicyId" TEXT,
    "dueAt" TIMESTAMP(3),
    "remediationPlanId" TEXT,
    "verificationState" TEXT NOT NULL DEFAULT 'NOT_REQUESTED',
    "regressionCount" INTEGER NOT NULL DEFAULT 0,
    "lastRegressionAt" TIMESTAMP(3),
    "verifiedFixedAt" TIMESTAMP(3),
    "closureSnapshot" JSONB,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "closedAt" TIMESTAMP(3),

    CONSTRAINT "RemediationCase_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationStatusHistory" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "fromStatus" TEXT,
    "toStatus" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "reason" TEXT,
    "evidence" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RemediationStatusHistory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationTriage" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "analystId" TEXT NOT NULL,
    "priority" TEXT,
    "reason" TEXT NOT NULL,
    "notes" TEXT,
    "evidence" JSONB,
    "canonicalFindingId" TEXT,
    "reviewAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RemediationTriage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationAssignment" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "ownerType" TEXT NOT NULL,
    "ownerId" TEXT,
    "teamId" TEXT,
    "confidence" TEXT,
    "assignedBy" TEXT NOT NULL,
    "reason" TEXT,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RemediationAssignment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationSlaSnapshot" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "policyId" TEXT,
    "policyVersion" INTEGER,
    "inputs" JSONB NOT NULL,
    "targetHours" DOUBLE PRECISION NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL,
    "dueAt" TIMESTAMP(3) NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'ON_TRACK',
    "pausedDurationMs" INTEGER NOT NULL DEFAULT 0,
    "pausedAt" TIMESTAMP(3),
    "pauseReason" TEXT,
    "completedAt" TIMESTAMP(3),
    "lastEvaluatedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationSlaSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationSlaPause" (
    "id" TEXT NOT NULL,
    "snapshotId" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "startedBy" TEXT NOT NULL,
    "approvedBy" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "endedBy" TEXT,

    CONSTRAINT "RemediationSlaPause_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationPlan" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "recommendedAction" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "patchReference" TEXT,
    "fixedVersion" TEXT,
    "targetVersion" TEXT,
    "mitigation" TEXT,
    "permanentFix" TEXT,
    "ownerId" TEXT,
    "plannedAt" TIMESTAMP(3),
    "targetDate" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationPlan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationWorkItem" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "integrationId" TEXT,
    "ticketId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "externalId" TEXT,
    "externalUrl" TEXT,
    "externalStatus" TEXT,
    "assignee" TEXT,
    "payload" JSONB,
    "failureCount" INTEGER NOT NULL DEFAULT 0,
    "lastError" TEXT,
    "nextRetryAt" TIMESTAMP(3),
    "lastSyncedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationWorkItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationFixClaim" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "claimedBy" TEXT NOT NULL,
    "claimSource" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "workItemId" TEXT,
    "deploymentRef" TEXT,
    "commitRef" TEXT,
    "patchRef" TEXT,
    "evidence" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RemediationFixClaim_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationVerificationJob" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "requestedBy" TEXT NOT NULL,
    "scannerProfile" TEXT,
    "scope" JSONB,
    "retestRequestId" TEXT,
    "requiredCleanObservations" INTEGER NOT NULL DEFAULT 1,
    "cleanObservations" INTEGER NOT NULL DEFAULT 0,
    "result" JSONB,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationVerificationJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationVerificationEvidence" (
    "id" TEXT NOT NULL,
    "jobId" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "beforeObservation" JSONB,
    "afterObservation" JSONB,
    "tool" TEXT,
    "toolVersion" TEXT,
    "comparisonResult" TEXT NOT NULL,
    "evidenceRefs" JSONB,
    "recordedBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RemediationVerificationEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationException" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "reason" TEXT NOT NULL,
    "scope" JSONB,
    "ownerId" TEXT NOT NULL,
    "requestedBy" TEXT NOT NULL,
    "approverId" TEXT,
    "compensatingControls" JSONB,
    "riskExceptionId" TEXT,
    "startsAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "reviewAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationException_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationCampaign" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "scope" JSONB NOT NULL,
    "ownerId" TEXT,
    "targetDate" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "idempotencyKey" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationCampaign_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationCampaignCase" (
    "id" TEXT NOT NULL,
    "campaignId" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RemediationCampaignCase_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationRegressionEvent" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "fingerprint" TEXT,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "previousVerifiedAt" TIMESTAMP(3),
    "source" TEXT NOT NULL,
    "riskRecalculation" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RemediationRegressionEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationReportSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "content" JSONB NOT NULL DEFAULT '{}',
    "contentHash" TEXT NOT NULL,
    "generatedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RemediationReportSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "RemediationCase_workspaceId_status_idx" ON "RemediationCase"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RemediationCase_workspaceId_findingId_idx" ON "RemediationCase"("workspaceId", "findingId");

-- CreateIndex
CREATE INDEX "RemediationCase_workspaceId_dueAt_idx" ON "RemediationCase"("workspaceId", "dueAt");

-- CreateIndex
CREATE INDEX "RemediationCase_workspaceId_ownerId_idx" ON "RemediationCase"("workspaceId", "ownerId");

-- CreateIndex
CREATE INDEX "RemediationStatusHistory_caseId_createdAt_idx" ON "RemediationStatusHistory"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "RemediationStatusHistory_workspaceId_idx" ON "RemediationStatusHistory"("workspaceId");

-- CreateIndex
CREATE INDEX "RemediationTriage_caseId_createdAt_idx" ON "RemediationTriage"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "RemediationTriage_workspaceId_idx" ON "RemediationTriage"("workspaceId");

-- CreateIndex
CREATE INDEX "RemediationAssignment_caseId_createdAt_idx" ON "RemediationAssignment"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "RemediationAssignment_workspaceId_ownerId_idx" ON "RemediationAssignment"("workspaceId", "ownerId");

-- CreateIndex
CREATE INDEX "RemediationSlaSnapshot_caseId_idx" ON "RemediationSlaSnapshot"("caseId");

-- CreateIndex
CREATE INDEX "RemediationSlaSnapshot_workspaceId_state_idx" ON "RemediationSlaSnapshot"("workspaceId", "state");

-- CreateIndex
CREATE INDEX "RemediationSlaSnapshot_workspaceId_dueAt_idx" ON "RemediationSlaSnapshot"("workspaceId", "dueAt");

-- CreateIndex
CREATE INDEX "RemediationSlaPause_snapshotId_idx" ON "RemediationSlaPause"("snapshotId");

-- CreateIndex
CREATE INDEX "RemediationSlaPause_workspaceId_idx" ON "RemediationSlaPause"("workspaceId");

-- CreateIndex
CREATE INDEX "RemediationPlan_caseId_createdAt_idx" ON "RemediationPlan"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "RemediationPlan_workspaceId_idx" ON "RemediationPlan"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "RemediationWorkItem_idempotencyKey_key" ON "RemediationWorkItem"("idempotencyKey");

-- CreateIndex
CREATE INDEX "RemediationWorkItem_caseId_idx" ON "RemediationWorkItem"("caseId");

-- CreateIndex
CREATE INDEX "RemediationWorkItem_workspaceId_status_idx" ON "RemediationWorkItem"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RemediationFixClaim_caseId_createdAt_idx" ON "RemediationFixClaim"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "RemediationFixClaim_workspaceId_idx" ON "RemediationFixClaim"("workspaceId");

-- CreateIndex
CREATE INDEX "RemediationVerificationJob_caseId_createdAt_idx" ON "RemediationVerificationJob"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "RemediationVerificationJob_workspaceId_status_idx" ON "RemediationVerificationJob"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RemediationVerificationEvidence_jobId_createdAt_idx" ON "RemediationVerificationEvidence"("jobId", "createdAt");

-- CreateIndex
CREATE INDEX "RemediationVerificationEvidence_workspaceId_idx" ON "RemediationVerificationEvidence"("workspaceId");

-- CreateIndex
CREATE INDEX "RemediationException_caseId_idx" ON "RemediationException"("caseId");

-- CreateIndex
CREATE INDEX "RemediationException_workspaceId_status_idx" ON "RemediationException"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RemediationException_expiresAt_idx" ON "RemediationException"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "RemediationCampaign_idempotencyKey_key" ON "RemediationCampaign"("idempotencyKey");

-- CreateIndex
CREATE INDEX "RemediationCampaign_workspaceId_status_idx" ON "RemediationCampaign"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RemediationCampaignCase_workspaceId_caseId_idx" ON "RemediationCampaignCase"("workspaceId", "caseId");

-- CreateIndex
CREATE UNIQUE INDEX "RemediationCampaignCase_campaignId_caseId_key" ON "RemediationCampaignCase"("campaignId", "caseId");

-- CreateIndex
CREATE INDEX "RemediationRegressionEvent_caseId_detectedAt_idx" ON "RemediationRegressionEvent"("caseId", "detectedAt");

-- CreateIndex
CREATE INDEX "RemediationRegressionEvent_workspaceId_detectedAt_idx" ON "RemediationRegressionEvent"("workspaceId", "detectedAt");

-- CreateIndex
CREATE INDEX "RemediationReportSnapshot_workspaceId_type_createdAt_idx" ON "RemediationReportSnapshot"("workspaceId", "type", "createdAt");

