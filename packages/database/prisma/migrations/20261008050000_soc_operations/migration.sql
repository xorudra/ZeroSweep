-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'TELEMETRY_SOURCE_CONNECTED';
ALTER TYPE "AuditAction" ADD VALUE 'TELEMETRY_EVENT_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'DETECTION_RULE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'DETECTION_RULE_ACTIVATED';
ALTER TYPE "AuditAction" ADD VALUE 'DETECTION_RULE_DISABLED';
ALTER TYPE "AuditAction" ADD VALUE 'DETECTION_MATCHED';
ALTER TYPE "AuditAction" ADD VALUE 'ALERT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'ALERT_TRIAGED';
ALTER TYPE "AuditAction" ADD VALUE 'ALERT_SUPPRESSED';
ALTER TYPE "AuditAction" ADD VALUE 'INCIDENT_DECLARED';
ALTER TYPE "AuditAction" ADD VALUE 'INCIDENT_STATUS_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'INCIDENT_EVIDENCE_ADDED';
ALTER TYPE "AuditAction" ADD VALUE 'RESPONSE_ACTION_PROPOSED';
ALTER TYPE "AuditAction" ADD VALUE 'RESPONSE_ACTION_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'RESPONSE_ACTION_EXECUTED';
ALTER TYPE "AuditAction" ADD VALUE 'PLAYBOOK_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'PLAYBOOK_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'THREAT_INTEL_SYNCED';
ALTER TYPE "AuditAction" ADD VALUE 'INDICATOR_MATCHED';
ALTER TYPE "AuditAction" ADD VALUE 'POST_INCIDENT_REVIEW_COMPLETED';

-- CreateTable
CREATE TABLE "SocTelemetrySource" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "sourceCategory" TEXT NOT NULL,
    "authReference" TEXT,
    "expectedIntervalSeconds" INTEGER,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "lastEventAt" TIMESTAMP(3),
    "lastIngestedAt" TIMESTAMP(3),
    "eventsIngested" INTEGER NOT NULL DEFAULT 0,
    "parseFailures" INTEGER NOT NULL DEFAULT 0,
    "authFailures" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SocTelemetrySource_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityTelemetryEvent" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "eventTime" TIMESTAMP(3) NOT NULL,
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT NOT NULL,
    "sourceCategory" TEXT NOT NULL,
    "eventCategory" TEXT NOT NULL,
    "eventAction" TEXT NOT NULL,
    "assetId" TEXT,
    "identityReference" TEXT,
    "severity" TEXT NOT NULL,
    "classification" TEXT NOT NULL DEFAULT 'INTERNAL',
    "attributes" JSONB NOT NULL DEFAULT '{}',
    "rawReference" TEXT,
    "schemaVersion" TEXT NOT NULL DEFAULT '1.0',
    "fingerprint" TEXT NOT NULL,
    "contentHash" TEXT NOT NULL,

    CONSTRAINT "SecurityTelemetryEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DetectionRule" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT,
    "templateKey" TEXT,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "category" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "currentVersion" INTEGER NOT NULL DEFAULT 0,
    "attackMappings" JSONB NOT NULL DEFAULT '[]',
    "dataSources" JSONB NOT NULL DEFAULT '[]',
    "matchCount" INTEGER NOT NULL DEFAULT 0,
    "lastMatchedAt" TIMESTAMP(3),
    "lastEvaluatedAt" TIMESTAMP(3),
    "evaluationFailures" INTEGER NOT NULL DEFAULT 0,
    "createdBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DetectionRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DetectionRuleVersion" (
    "id" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "definition" JSONB NOT NULL,
    "createdBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DetectionRuleVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DetectionMatch" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "ruleVersion" INTEGER NOT NULL,
    "eventIds" JSONB NOT NULL DEFAULT '[]',
    "matchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "severity" TEXT NOT NULL,
    "confidence" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "assetId" TEXT,
    "identityReference" TEXT,
    "indicatorId" TEXT,
    "groupKey" TEXT,
    "alertId" TEXT,

    CONSTRAINT "DetectionMatch_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityAlert" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "severity" TEXT NOT NULL,
    "priority" TEXT NOT NULL,
    "priorityScore" INTEGER NOT NULL DEFAULT 0,
    "priorityFactors" JSONB NOT NULL DEFAULT '{}',
    "status" TEXT NOT NULL DEFAULT 'NEW',
    "source" TEXT NOT NULL,
    "ruleId" TEXT,
    "assetId" TEXT,
    "identityReference" TEXT,
    "indicatorId" TEXT,
    "findingId" TEXT,
    "ownerId" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "occurrenceCount" INTEGER NOT NULL DEFAULT 1,
    "acknowledgedAt" TIMESTAMP(3),
    "containedAt" TIMESTAMP(3),
    "resolvedAt" TIMESTAMP(3),
    "slaBreached" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityAlert_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AlertTriage" (
    "id" TEXT NOT NULL,
    "alertId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "analystId" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "reason" TEXT NOT NULL DEFAULT '',
    "notes" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AlertTriage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AlertSuppressionRule" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "ruleId" TEXT,
    "assetId" TEXT,
    "identityReference" TEXT,
    "reason" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "approvedBy" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AlertSuppressionRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityIncident" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "severity" TEXT NOT NULL,
    "priority" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "category" TEXT NOT NULL DEFAULT 'GENERAL',
    "commanderId" TEXT,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "declaredAt" TIMESTAMP(3),
    "containedAt" TIMESTAMP(3),
    "recoveredAt" TIMESTAMP(3),
    "closedAt" TIMESTAMP(3),
    "businessImpact" TEXT NOT NULL DEFAULT '',
    "classification" TEXT NOT NULL DEFAULT 'INTERNAL',
    "caseId" TEXT,
    "createdBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityIncident_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentLink" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "createdBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentTimelineEntry" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "entryType" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "detail" JSONB NOT NULL DEFAULT '{}',
    "actorId" TEXT,
    "amendsEntryId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentTimelineEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentEvidence" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "classification" TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    "contentHash" TEXT NOT NULL,
    "objectReference" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "relatedEventId" TEXT,
    "relatedAssetId" TEXT,
    "collectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "collectedBy" TEXT NOT NULL,
    "chainMetadata" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentEvidenceAccess" (
    "id" TEXT NOT NULL,
    "evidenceId" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "result" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentEvidenceAccess_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "InvestigationCase" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "severity" TEXT NOT NULL DEFAULT 'MEDIUM',
    "ownerId" TEXT,
    "linkedAlertIds" JSONB NOT NULL DEFAULT '[]',
    "linkedEventIds" JSONB NOT NULL DEFAULT '[]',
    "escalatedIncidentId" TEXT,
    "createdBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InvestigationCase_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ThreatIntelSource" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "trustLevel" INTEGER NOT NULL DEFAULT 50,
    "authenticationReference" TEXT,
    "syncFrequencyMinutes" INTEGER,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "transportStatus" TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ThreatIntelSource_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ThreatIndicator" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "valueNormalized" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 0,
    "severity" TEXT NOT NULL DEFAULT 'MEDIUM',
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "validUntil" TIMESTAMP(3),
    "tags" JSONB NOT NULL DEFAULT '[]',
    "references" JSONB NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ThreatIndicator_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IndicatorObservation" (
    "id" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confidence" INTEGER,
    "stixId" TEXT,
    "detail" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "IndicatorObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IndicatorMatch" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,
    "telemetryEventId" TEXT,
    "assetId" TEXT,
    "identityReference" TEXT,
    "matchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confidence" INTEGER NOT NULL,
    "context" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "IndicatorMatch_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ThreatIntelFeedSync" (
    "id" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "indicatorsIn" INTEGER NOT NULL DEFAULT 0,
    "created" INTEGER NOT NULL DEFAULT 0,
    "updated" INTEGER NOT NULL DEFAULT 0,
    "errors" JSONB NOT NULL DEFAULT '[]',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "ThreatIntelFeedSync_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ResponseActionExecution" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "actionKey" TEXT NOT NULL,
    "targetReference" TEXT NOT NULL,
    "executionId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PROPOSED',
    "proposedBy" TEXT NOT NULL,
    "result" JSONB NOT NULL DEFAULT '{}',
    "rollback" JSONB NOT NULL DEFAULT '{}',
    "executedAt" TIMESTAMP(3),
    "executedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ResponseActionExecution_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ResponseActionApproval" (
    "id" TEXT NOT NULL,
    "executionId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "approverId" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "reason" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ResponseActionApproval_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentPlaybookRun" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "playbookKey" TEXT NOT NULL,
    "playbookVersion" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'RUNNING',
    "currentStepKey" TEXT,
    "stepsState" JSONB NOT NULL DEFAULT '[]',
    "startedBy" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "IncidentPlaybookRun_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentCommunication" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "audience" TEXT NOT NULL,
    "channel" TEXT NOT NULL,
    "template" TEXT,
    "messageSnapshot" TEXT NOT NULL,
    "authorId" TEXT NOT NULL,
    "deliveryStatus" TEXT NOT NULL DEFAULT 'RECORDED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentCommunication_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PostIncidentReview" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "summary" TEXT NOT NULL DEFAULT '',
    "impact" TEXT NOT NULL DEFAULT '',
    "rootCause" TEXT NOT NULL DEFAULT '',
    "rootCauseState" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "detectionGaps" JSONB NOT NULL DEFAULT '[]',
    "responseGaps" JSONB NOT NULL DEFAULT '[]',
    "lessons" JSONB NOT NULL DEFAULT '[]',
    "followUpActions" JSONB NOT NULL DEFAULT '[]',
    "ownerId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PostIncidentReview_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SocSlaConfig" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targets" JSONB NOT NULL DEFAULT '{}',
    "updatedBy" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SocSlaConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TelemetryDataGap" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "sourceName" TEXT NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastEventAt" TIMESTAMP(3),
    "gapSeconds" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "resolvedAt" TIMESTAMP(3),

    CONSTRAINT "TelemetryDataGap_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SocIncidentReport" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "content" JSONB NOT NULL DEFAULT '{}',
    "contentHash" TEXT NOT NULL,
    "generatedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SocIncidentReport_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SocTelemetrySource_workspaceId_enabled_idx" ON "SocTelemetrySource"("workspaceId", "enabled");

-- CreateIndex
CREATE UNIQUE INDEX "SocTelemetrySource_workspaceId_name_key" ON "SocTelemetrySource"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "SecurityTelemetryEvent_workspaceId_eventTime_idx" ON "SecurityTelemetryEvent"("workspaceId", "eventTime");

-- CreateIndex
CREATE INDEX "SecurityTelemetryEvent_workspaceId_eventCategory_eventActio_idx" ON "SecurityTelemetryEvent"("workspaceId", "eventCategory", "eventAction");

-- CreateIndex
CREATE INDEX "SecurityTelemetryEvent_workspaceId_assetId_idx" ON "SecurityTelemetryEvent"("workspaceId", "assetId");

-- CreateIndex
CREATE INDEX "SecurityTelemetryEvent_workspaceId_identityReference_idx" ON "SecurityTelemetryEvent"("workspaceId", "identityReference");

-- CreateIndex
CREATE INDEX "SecurityTelemetryEvent_workspaceId_source_idx" ON "SecurityTelemetryEvent"("workspaceId", "source");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityTelemetryEvent_workspaceId_fingerprint_key" ON "SecurityTelemetryEvent"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "DetectionRule_workspaceId_status_idx" ON "DetectionRule"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "DetectionRule_workspaceId_category_idx" ON "DetectionRule"("workspaceId", "category");

-- CreateIndex
CREATE INDEX "DetectionRuleVersion_ruleId_idx" ON "DetectionRuleVersion"("ruleId");

-- CreateIndex
CREATE UNIQUE INDEX "DetectionRuleVersion_ruleId_version_key" ON "DetectionRuleVersion"("ruleId", "version");

-- CreateIndex
CREATE INDEX "DetectionMatch_workspaceId_ruleId_matchedAt_idx" ON "DetectionMatch"("workspaceId", "ruleId", "matchedAt");

-- CreateIndex
CREATE INDEX "DetectionMatch_workspaceId_alertId_idx" ON "DetectionMatch"("workspaceId", "alertId");

-- CreateIndex
CREATE INDEX "SecurityAlert_workspaceId_status_priority_idx" ON "SecurityAlert"("workspaceId", "status", "priority");

-- CreateIndex
CREATE INDEX "SecurityAlert_workspaceId_fingerprint_idx" ON "SecurityAlert"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "SecurityAlert_workspaceId_assetId_idx" ON "SecurityAlert"("workspaceId", "assetId");

-- CreateIndex
CREATE INDEX "SecurityAlert_workspaceId_ruleId_idx" ON "SecurityAlert"("workspaceId", "ruleId");

-- CreateIndex
CREATE INDEX "AlertTriage_workspaceId_alertId_idx" ON "AlertTriage"("workspaceId", "alertId");

-- CreateIndex
CREATE INDEX "AlertSuppressionRule_workspaceId_expiresAt_idx" ON "AlertSuppressionRule"("workspaceId", "expiresAt");

-- CreateIndex
CREATE INDEX "SecurityIncident_workspaceId_status_priority_idx" ON "SecurityIncident"("workspaceId", "status", "priority");

-- CreateIndex
CREATE INDEX "SecurityIncident_workspaceId_detectedAt_idx" ON "SecurityIncident"("workspaceId", "detectedAt");

-- CreateIndex
CREATE INDEX "IncidentLink_workspaceId_incidentId_idx" ON "IncidentLink"("workspaceId", "incidentId");

-- CreateIndex
CREATE UNIQUE INDEX "IncidentLink_incidentId_resourceType_resourceId_key" ON "IncidentLink"("incidentId", "resourceType", "resourceId");

-- CreateIndex
CREATE INDEX "IncidentTimelineEntry_workspaceId_incidentId_createdAt_idx" ON "IncidentTimelineEntry"("workspaceId", "incidentId", "createdAt");

-- CreateIndex
CREATE INDEX "IncidentEvidence_workspaceId_incidentId_idx" ON "IncidentEvidence"("workspaceId", "incidentId");

-- CreateIndex
CREATE INDEX "IncidentEvidenceAccess_workspaceId_evidenceId_createdAt_idx" ON "IncidentEvidenceAccess"("workspaceId", "evidenceId", "createdAt");

-- CreateIndex
CREATE INDEX "InvestigationCase_workspaceId_status_idx" ON "InvestigationCase"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "ThreatIntelSource_workspaceId_enabled_idx" ON "ThreatIntelSource"("workspaceId", "enabled");

-- CreateIndex
CREATE UNIQUE INDEX "ThreatIntelSource_workspaceId_name_key" ON "ThreatIntelSource"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "ThreatIndicator_workspaceId_status_idx" ON "ThreatIndicator"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "ThreatIndicator_workspaceId_type_idx" ON "ThreatIndicator"("workspaceId", "type");

-- CreateIndex
CREATE UNIQUE INDEX "ThreatIndicator_workspaceId_type_valueNormalized_key" ON "ThreatIndicator"("workspaceId", "type", "valueNormalized");

-- CreateIndex
CREATE INDEX "IndicatorObservation_workspaceId_indicatorId_idx" ON "IndicatorObservation"("workspaceId", "indicatorId");

-- CreateIndex
CREATE INDEX "IndicatorObservation_workspaceId_sourceId_idx" ON "IndicatorObservation"("workspaceId", "sourceId");

-- CreateIndex
CREATE INDEX "IndicatorMatch_workspaceId_indicatorId_matchedAt_idx" ON "IndicatorMatch"("workspaceId", "indicatorId", "matchedAt");

-- CreateIndex
CREATE INDEX "IndicatorMatch_workspaceId_telemetryEventId_idx" ON "IndicatorMatch"("workspaceId", "telemetryEventId");

-- CreateIndex
CREATE INDEX "ThreatIntelFeedSync_workspaceId_sourceId_startedAt_idx" ON "ThreatIntelFeedSync"("workspaceId", "sourceId", "startedAt");

-- CreateIndex
CREATE INDEX "ResponseActionExecution_workspaceId_incidentId_idx" ON "ResponseActionExecution"("workspaceId", "incidentId");

-- CreateIndex
CREATE UNIQUE INDEX "ResponseActionExecution_workspaceId_executionId_key" ON "ResponseActionExecution"("workspaceId", "executionId");

-- CreateIndex
CREATE INDEX "ResponseActionApproval_workspaceId_executionId_idx" ON "ResponseActionApproval"("workspaceId", "executionId");

-- CreateIndex
CREATE UNIQUE INDEX "ResponseActionApproval_executionId_approverId_key" ON "ResponseActionApproval"("executionId", "approverId");

-- CreateIndex
CREATE INDEX "IncidentPlaybookRun_workspaceId_incidentId_idx" ON "IncidentPlaybookRun"("workspaceId", "incidentId");

-- CreateIndex
CREATE INDEX "IncidentCommunication_workspaceId_incidentId_createdAt_idx" ON "IncidentCommunication"("workspaceId", "incidentId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "PostIncidentReview_incidentId_key" ON "PostIncidentReview"("incidentId");

-- CreateIndex
CREATE INDEX "PostIncidentReview_workspaceId_status_idx" ON "PostIncidentReview"("workspaceId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "SocSlaConfig_workspaceId_key" ON "SocSlaConfig"("workspaceId");

-- CreateIndex
CREATE INDEX "TelemetryDataGap_workspaceId_status_idx" ON "TelemetryDataGap"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "TelemetryDataGap_workspaceId_sourceId_idx" ON "TelemetryDataGap"("workspaceId", "sourceId");

-- CreateIndex
CREATE INDEX "SocIncidentReport_workspaceId_incidentId_createdAt_idx" ON "SocIncidentReport"("workspaceId", "incidentId", "createdAt");

