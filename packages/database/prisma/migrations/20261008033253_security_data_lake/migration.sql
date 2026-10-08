-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'SECURITY_SEARCH_EXECUTED';
ALTER TYPE "AuditAction" ADD VALUE 'ANALYTICS_EXPORTED';
ALTER TYPE "AuditAction" ADD VALUE 'ATTACK_PATH_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'ANALYTICS_INGESTION_RUN';
ALTER TYPE "AuditAction" ADD VALUE 'ANALYTICS_REINDEX_RUN';
ALTER TYPE "AuditAction" ADD VALUE 'ANALYTICS_RETENTION_RUN';
ALTER TYPE "AuditAction" ADD VALUE 'SAVED_QUERY_CREATED';

-- CreateTable
CREATE TABLE "SecurityAnalyticsEvent" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "eventTime" TIMESTAMP(3) NOT NULL,
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sourceType" TEXT NOT NULL,
    "sourceId" TEXT,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "assetId" TEXT,
    "findingId" TEXT,
    "scanId" TEXT,
    "severity" TEXT,
    "priority" TEXT,
    "riskScore" DOUBLE PRECISION,
    "classification" TEXT NOT NULL DEFAULT 'INTERNAL',
    "schemaVersion" TEXT NOT NULL DEFAULT '1.0',
    "attributes" JSONB NOT NULL DEFAULT '{}',
    "checksum" TEXT NOT NULL,

    CONSTRAINT "SecurityAnalyticsEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AnalyticsIngestionCheckpoint" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "consumer" TEXT NOT NULL,
    "partition" TEXT NOT NULL,
    "lastEventKey" TEXT,
    "lastEventAt" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'IDLE',
    "processed" INTEGER NOT NULL DEFAULT 0,
    "rejected" INTEGER NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AnalyticsIngestionCheckpoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AnalyticsDeadLetterEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT,
    "eventId" TEXT,
    "sourceType" TEXT NOT NULL,
    "rawSummary" JSONB NOT NULL DEFAULT '{}',
    "errors" JSONB NOT NULL DEFAULT '[]',
    "status" TEXT NOT NULL DEFAULT 'QUARANTINED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),

    CONSTRAINT "AnalyticsDeadLetterEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecuritySearchDocument" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "documentType" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "summary" TEXT NOT NULL DEFAULT '',
    "searchableText" TEXT NOT NULL,
    "facets" JSONB NOT NULL DEFAULT '{}',
    "classification" TEXT NOT NULL DEFAULT 'INTERNAL',
    "riskScore" DOUBLE PRECISION,
    "severity" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecuritySearchDocument_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SavedSecurityQuery" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "queryText" TEXT NOT NULL,
    "filters" JSONB NOT NULL DEFAULT '{}',
    "visibility" TEXT NOT NULL DEFAULT 'PRIVATE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SavedSecurityQuery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssetSecuritySnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "exposure" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'UNSPECIFIED',
    "technologies" JSONB NOT NULL DEFAULT '[]',
    "services" JSONB NOT NULL DEFAULT '[]',
    "findingCounts" JSONB NOT NULL DEFAULT '{}',
    "riskScore" DOUBLE PRECISION,
    "postureState" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "stateHash" TEXT NOT NULL,

    CONSTRAINT "AssetSecuritySnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingLifecycleProjection" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "triagedAt" TIMESTAMP(3),
    "verifiedAt" TIMESTAMP(3),
    "resolvedAt" TIMESTAMP(3),
    "reopenedAt" TIMESTAMP(3),
    "regressionCount" INTEGER NOT NULL DEFAULT 0,
    "remediationSeconds" INTEGER,
    "currentStatus" TEXT NOT NULL DEFAULT 'OPEN',
    "severity" TEXT,
    "cwe" TEXT,
    "cve" TEXT,
    "assetId" TEXT,
    "repositoryId" TEXT,
    "rebuiltAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingLifecycleProjection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskHistoryProjection" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT,
    "assetId" TEXT,
    "recordedAt" TIMESTAMP(3) NOT NULL,
    "riskScore" DOUBLE PRECISION,
    "priority" TEXT,
    "kevListed" BOOLEAN NOT NULL DEFAULT false,
    "epssScore" DOUBLE PRECISION,
    "verificationState" TEXT,
    "criticality" TEXT,
    "sourceEventId" TEXT,

    CONSTRAINT "RiskHistoryProjection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ExposureSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "internetFacingAssets" INTEGER NOT NULL DEFAULT 0,
    "totalAssets" INTEGER NOT NULL DEFAULT 0,
    "openServices" INTEGER NOT NULL DEFAULT 0,
    "newServices" INTEGER NOT NULL DEFAULT 0,
    "removedServices" INTEGER NOT NULL DEFAULT 0,
    "highRiskTechnologies" INTEGER NOT NULL DEFAULT 0,
    "criticalFindings" INTEGER NOT NULL DEFAULT 0,
    "kevFindings" INTEGER NOT NULL DEFAULT 0,
    "unknownAssets" INTEGER NOT NULL DEFAULT 0,
    "contentHash" TEXT NOT NULL,

    CONSTRAINT "ExposureSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ShadowAssetSignal" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT,
    "host" TEXT NOT NULL,
    "signalType" TEXT NOT NULL,
    "evidence" JSONB NOT NULL DEFAULT '{}',
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ShadowAssetSignal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CorrelationRule" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "inputTypes" JSONB NOT NULL DEFAULT '[]',
    "conditions" JSONB NOT NULL DEFAULT '[]',
    "severity" TEXT NOT NULL DEFAULT 'MEDIUM',
    "outputType" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "version" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CorrelationRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityCorrelationSignal" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "ruleId" TEXT,
    "signalType" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'MEDIUM',
    "confidence" TEXT NOT NULL DEFAULT 'LOW',
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "assetId" TEXT,
    "findingId" TEXT,
    "resourceType" TEXT,
    "resourceId" TEXT,
    "evidence" JSONB NOT NULL DEFAULT '{}',
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "occurrenceCount" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityCorrelationSignal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AttackPathCandidate" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "score" DOUBLE PRECISION NOT NULL,
    "confidence" TEXT NOT NULL DEFAULT 'LOW',
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "nodes" JSONB NOT NULL DEFAULT '[]',
    "edges" JSONB NOT NULL DEFAULT '[]',
    "assetId" TEXT,
    "findingId" TEXT,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AttackPathCandidate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AnalyticsRetentionPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "eventRetentionDays" INTEGER NOT NULL DEFAULT 730,
    "searchDocRetentionDays" INTEGER NOT NULL DEFAULT 730,
    "snapshotRetentionDays" INTEGER NOT NULL DEFAULT 365,
    "restrictedEventRetentionDays" INTEGER NOT NULL DEFAULT 365,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AnalyticsRetentionPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecuritySearchReindexJob" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "documentType" TEXT,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "indexedCount" INTEGER NOT NULL DEFAULT 0,
    "requestedBy" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "errorSummary" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecuritySearchReindexJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AnalyticsDashboardSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "view" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT NOT NULL DEFAULT 'MANUAL',
    "content" JSONB NOT NULL DEFAULT '{}',
    "contentHash" TEXT NOT NULL,
    "generatedBy" TEXT,

    CONSTRAINT "AnalyticsDashboardSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "SecurityAnalyticsEvent_eventId_key" ON "SecurityAnalyticsEvent"("eventId");

-- CreateIndex
CREATE INDEX "SecurityAnalyticsEvent_organizationId_workspaceId_idx" ON "SecurityAnalyticsEvent"("organizationId", "workspaceId");

-- CreateIndex
CREATE INDEX "SecurityAnalyticsEvent_workspaceId_eventTime_idx" ON "SecurityAnalyticsEvent"("workspaceId", "eventTime");

-- CreateIndex
CREATE INDEX "SecurityAnalyticsEvent_workspaceId_eventType_idx" ON "SecurityAnalyticsEvent"("workspaceId", "eventType");

-- CreateIndex
CREATE INDEX "SecurityAnalyticsEvent_workspaceId_assetId_idx" ON "SecurityAnalyticsEvent"("workspaceId", "assetId");

-- CreateIndex
CREATE INDEX "SecurityAnalyticsEvent_workspaceId_findingId_idx" ON "SecurityAnalyticsEvent"("workspaceId", "findingId");

-- CreateIndex
CREATE INDEX "SecurityAnalyticsEvent_workspaceId_severity_idx" ON "SecurityAnalyticsEvent"("workspaceId", "severity");

-- CreateIndex
CREATE INDEX "SecurityAnalyticsEvent_workspaceId_riskScore_idx" ON "SecurityAnalyticsEvent"("workspaceId", "riskScore");

-- CreateIndex
CREATE INDEX "SecurityAnalyticsEvent_workspaceId_classification_idx" ON "SecurityAnalyticsEvent"("workspaceId", "classification");

-- CreateIndex
CREATE INDEX "AnalyticsIngestionCheckpoint_workspaceId_status_idx" ON "AnalyticsIngestionCheckpoint"("workspaceId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "AnalyticsIngestionCheckpoint_workspaceId_consumer_partition_key" ON "AnalyticsIngestionCheckpoint"("workspaceId", "consumer", "partition");

-- CreateIndex
CREATE INDEX "AnalyticsDeadLetterEvent_workspaceId_status_idx" ON "AnalyticsDeadLetterEvent"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AnalyticsDeadLetterEvent_createdAt_idx" ON "AnalyticsDeadLetterEvent"("createdAt");

-- CreateIndex
CREATE INDEX "SecuritySearchDocument_organizationId_workspaceId_idx" ON "SecuritySearchDocument"("organizationId", "workspaceId");

-- CreateIndex
CREATE INDEX "SecuritySearchDocument_workspaceId_documentType_idx" ON "SecuritySearchDocument"("workspaceId", "documentType");

-- CreateIndex
CREATE INDEX "SecuritySearchDocument_workspaceId_classification_idx" ON "SecuritySearchDocument"("workspaceId", "classification");

-- CreateIndex
CREATE INDEX "SecuritySearchDocument_workspaceId_severity_idx" ON "SecuritySearchDocument"("workspaceId", "severity");

-- CreateIndex
CREATE UNIQUE INDEX "SecuritySearchDocument_workspaceId_documentType_resourceId_key" ON "SecuritySearchDocument"("workspaceId", "documentType", "resourceId");

-- CreateIndex
CREATE INDEX "SavedSecurityQuery_workspaceId_userId_idx" ON "SavedSecurityQuery"("workspaceId", "userId");

-- CreateIndex
CREATE INDEX "SavedSecurityQuery_workspaceId_visibility_idx" ON "SavedSecurityQuery"("workspaceId", "visibility");

-- CreateIndex
CREATE INDEX "AssetSecuritySnapshot_workspaceId_assetId_capturedAt_idx" ON "AssetSecuritySnapshot"("workspaceId", "assetId", "capturedAt");

-- CreateIndex
CREATE INDEX "AssetSecuritySnapshot_workspaceId_capturedAt_idx" ON "AssetSecuritySnapshot"("workspaceId", "capturedAt");

-- CreateIndex
CREATE INDEX "FindingLifecycleProjection_workspaceId_currentStatus_idx" ON "FindingLifecycleProjection"("workspaceId", "currentStatus");

-- CreateIndex
CREATE INDEX "FindingLifecycleProjection_workspaceId_severity_idx" ON "FindingLifecycleProjection"("workspaceId", "severity");

-- CreateIndex
CREATE UNIQUE INDEX "FindingLifecycleProjection_workspaceId_findingId_key" ON "FindingLifecycleProjection"("workspaceId", "findingId");

-- CreateIndex
CREATE INDEX "RiskHistoryProjection_workspaceId_recordedAt_idx" ON "RiskHistoryProjection"("workspaceId", "recordedAt");

-- CreateIndex
CREATE INDEX "RiskHistoryProjection_workspaceId_findingId_recordedAt_idx" ON "RiskHistoryProjection"("workspaceId", "findingId", "recordedAt");

-- CreateIndex
CREATE INDEX "RiskHistoryProjection_workspaceId_assetId_recordedAt_idx" ON "RiskHistoryProjection"("workspaceId", "assetId", "recordedAt");

-- CreateIndex
CREATE INDEX "ExposureSnapshot_workspaceId_capturedAt_idx" ON "ExposureSnapshot"("workspaceId", "capturedAt");

-- CreateIndex
CREATE INDEX "ShadowAssetSignal_workspaceId_status_idx" ON "ShadowAssetSignal"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "ShadowAssetSignal_workspaceId_detectedAt_idx" ON "ShadowAssetSignal"("workspaceId", "detectedAt");

-- CreateIndex
CREATE INDEX "CorrelationRule_workspaceId_enabled_idx" ON "CorrelationRule"("workspaceId", "enabled");

-- CreateIndex
CREATE INDEX "SecurityCorrelationSignal_workspaceId_status_idx" ON "SecurityCorrelationSignal"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "SecurityCorrelationSignal_workspaceId_signalType_idx" ON "SecurityCorrelationSignal"("workspaceId", "signalType");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityCorrelationSignal_workspaceId_fingerprint_key" ON "SecurityCorrelationSignal"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "AttackPathCandidate_workspaceId_status_idx" ON "AttackPathCandidate"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AttackPathCandidate_workspaceId_score_idx" ON "AttackPathCandidate"("workspaceId", "score");

-- CreateIndex
CREATE UNIQUE INDEX "AttackPathCandidate_workspaceId_fingerprint_key" ON "AttackPathCandidate"("workspaceId", "fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "AnalyticsRetentionPolicy_workspaceId_key" ON "AnalyticsRetentionPolicy"("workspaceId");

-- CreateIndex
CREATE INDEX "SecuritySearchReindexJob_workspaceId_status_idx" ON "SecuritySearchReindexJob"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AnalyticsDashboardSnapshot_workspaceId_view_capturedAt_idx" ON "AnalyticsDashboardSnapshot"("workspaceId", "view", "capturedAt");
