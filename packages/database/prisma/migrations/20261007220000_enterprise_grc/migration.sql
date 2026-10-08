-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'FRAMEWORK_IMPORTED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTROL_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTROL_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTROL_TESTED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTROL_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTROL_RECOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'EVIDENCE_COLLECTED';
ALTER TYPE "AuditAction" ADD VALUE 'EVIDENCE_UPLOADED';
ALTER TYPE "AuditAction" ADD VALUE 'EVIDENCE_EXPIRED';
ALTER TYPE "AuditAction" ADD VALUE 'GRC_ASSESSMENT_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'RISK_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'POLICY_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'AUDIT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'AUDIT_EVIDENCE_SUBMITTED';
ALTER TYPE "AuditAction" ADD VALUE 'AUDIT_EVIDENCE_ACCEPTED';
ALTER TYPE "AuditAction" ADD VALUE 'AUDIT_PACKAGE_GENERATED';

-- DropIndex
DROP INDEX "ComplianceFramework_key_key";

-- AlterTable
ALTER TABLE "ComplianceFramework" ADD COLUMN     "effectiveDate" TIMESTAMP(3),
ADD COLUMN     "metadata" JSONB NOT NULL DEFAULT '{}',
ADD COLUMN     "publisher" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "retiredDate" TIMESTAMP(3),
ADD COLUMN     "status" TEXT NOT NULL DEFAULT 'ACTIVE';

-- CreateTable
CREATE TABLE "ComplianceRequirement" (
    "id" TEXT NOT NULL,
    "frameworkId" TEXT NOT NULL,
    "requirementId" TEXT NOT NULL,
    "parentRequirementId" TEXT,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "category" TEXT NOT NULL DEFAULT '',
    "level" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "ComplianceRequirement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityControl" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "controlType" TEXT NOT NULL,
    "implementationType" TEXT NOT NULL,
    "implementationStatus" TEXT NOT NULL DEFAULT 'NOT_IMPLEMENTED',
    "effectiveness" TEXT NOT NULL DEFAULT 'NOT_TESTED',
    "catalogSource" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityControl_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlOwner" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "ownerType" TEXT NOT NULL,
    "ownerRef" TEXT NOT NULL,
    "isPrimary" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ControlOwner_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlFrameworkMapping" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "requirementId" TEXT NOT NULL,
    "mappingType" TEXT NOT NULL,
    "coverage" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "notes" TEXT NOT NULL DEFAULT '',
    "source" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ControlFrameworkMapping_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlTest" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "automationLevel" TEXT NOT NULL,
    "frequency" TEXT NOT NULL DEFAULT 'CONTINUOUS',
    "expectedResult" TEXT NOT NULL DEFAULT '',
    "evidenceRequirements" TEXT NOT NULL DEFAULT '',
    "ownerRef" TEXT,
    "signalKeys" JSONB NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ControlTest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlSignal" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "signalKey" TEXT NOT NULL,
    "state" TEXT,
    "detail" TEXT NOT NULL DEFAULT '',
    "evidenceRefs" JSONB NOT NULL DEFAULT '[]',
    "sourceType" TEXT NOT NULL DEFAULT '',
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ControlSignal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlEvaluation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "result" TEXT NOT NULL,
    "confidence" TEXT NOT NULL,
    "effectiveness" TEXT NOT NULL DEFAULT 'NOT_TESTED',
    "reason" TEXT NOT NULL DEFAULT '',
    "evidenceRefs" JSONB NOT NULL DEFAULT '[]',
    "evaluatedBy" TEXT NOT NULL DEFAULT 'SYSTEM',
    "evaluatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ControlEvaluation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ComplianceEvidence" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "sourceType" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "snapshot" JSONB NOT NULL DEFAULT '{}',
    "classification" TEXT NOT NULL DEFAULT 'INTERNAL',
    "status" TEXT NOT NULL DEFAULT 'CURRENT',
    "hash" TEXT NOT NULL,
    "filename" TEXT,
    "mimeType" TEXT,
    "sizeBytes" INTEGER,
    "collectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "validFrom" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "validUntil" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "reviewStatus" TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
    "reviewedBy" TEXT,
    "reviewNotes" TEXT,

    CONSTRAINT "ComplianceEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EvidenceFreshnessPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "staleAfterDays" INTEGER NOT NULL,
    "expireAfterDays" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EvidenceFreshnessPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ComplianceAssessment" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "frameworkId" TEXT NOT NULL,
    "frameworkKey" TEXT NOT NULL,
    "frameworkVersion" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "scope" JSONB NOT NULL DEFAULT '{}',
    "periodStart" TIMESTAMP(3),
    "periodEnd" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'PLANNED',
    "ownerId" TEXT NOT NULL,
    "reviewerId" TEXT,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ComplianceAssessment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssessmentRequirementResult" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assessmentId" TEXT NOT NULL,
    "requirementId" TEXT NOT NULL,
    "result" TEXT NOT NULL,
    "controlIds" JSONB NOT NULL DEFAULT '[]',
    "evidenceIds" JSONB NOT NULL DEFAULT '[]',
    "exceptionIds" JSONB NOT NULL DEFAULT '[]',
    "notes" TEXT NOT NULL DEFAULT '',
    "reviewStatus" TEXT NOT NULL DEFAULT 'PENDING',
    "reviewedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AssessmentRequirementResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ComplianceDriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT,
    "type" TEXT NOT NULL,
    "detail" TEXT NOT NULL DEFAULT '',
    "previousResult" TEXT,
    "newResult" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ComplianceDriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlTestSchedule" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "cron" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "lastRunAt" TIMESTAMP(3),
    "nextRunAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ControlTestSchedule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskRegister" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL DEFAULT 'Risk Register',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskRegister_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskMatrix" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "config" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskMatrix_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskRecord" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "registerId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "category" TEXT NOT NULL DEFAULT 'SECURITY',
    "source" TEXT NOT NULL,
    "sourceRef" TEXT,
    "likelihood" INTEGER NOT NULL,
    "impacts" JSONB NOT NULL DEFAULT '{}',
    "inherentScore" INTEGER NOT NULL,
    "inherentBand" TEXT NOT NULL,
    "residualScore" INTEGER,
    "residualBand" TEXT,
    "residualBasis" TEXT NOT NULL DEFAULT '',
    "ownerId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'IDENTIFIED',
    "treatment" TEXT,
    "reviewDate" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskLink" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "riskId" TEXT NOT NULL,
    "linkType" TEXT NOT NULL,
    "linkId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RiskLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskTreatmentPlan" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "riskId" TEXT NOT NULL,
    "strategy" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'PLANNED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskTreatmentPlan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskTreatmentAction" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "planId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "dueDate" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "relatedFindingId" TEXT,
    "relatedControlId" TEXT,
    "ticketRef" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskTreatmentAction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskAcceptance" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "riskId" TEXT NOT NULL,
    "requestedBy" TEXT NOT NULL,
    "approvedBy" TEXT,
    "reason" TEXT NOT NULL,
    "scope" JSONB NOT NULL DEFAULT '{}',
    "compensatingControls" JSONB NOT NULL DEFAULT '[]',
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskAcceptance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskReview" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "riskId" TEXT NOT NULL,
    "reviewerId" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "changes" TEXT NOT NULL DEFAULT '',
    "nextReviewAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RiskReview_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GovernancePolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "effectiveDate" TIMESTAMP(3),
    "reviewDate" TIMESTAMP(3),
    "classification" TEXT NOT NULL DEFAULT 'INTERNAL',
    "documentRef" TEXT NOT NULL DEFAULT '',
    "contentHash" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GovernancePolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PolicyAcknowledgement" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "policyId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "acknowledgedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PolicyAcknowledgement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEngagement" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "frameworkId" TEXT,
    "assessmentId" TEXT,
    "type" TEXT NOT NULL,
    "auditorRef" TEXT NOT NULL DEFAULT '',
    "scope" JSONB NOT NULL DEFAULT '{}',
    "periodStart" TIMESTAMP(3),
    "periodEnd" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'PLANNED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuditEngagement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEvidenceRequest" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "auditId" TEXT NOT NULL,
    "controlId" TEXT,
    "requirementId" TEXT,
    "title" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "dueDate" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "evidenceIds" JSONB NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuditEvidenceRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditFinding" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "auditId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "severity" TEXT NOT NULL DEFAULT 'MEDIUM',
    "requirementId" TEXT,
    "ownerId" TEXT NOT NULL,
    "dueDate" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "remediation" TEXT NOT NULL DEFAULT '',
    "linkedFindingIds" JSONB NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuditFinding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEvidencePackage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "auditId" TEXT NOT NULL,
    "assessmentId" TEXT NOT NULL,
    "frameworkKey" TEXT NOT NULL,
    "frameworkVersion" TEXT NOT NULL,
    "classification" TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    "manifest" JSONB NOT NULL DEFAULT '{}',
    "manifestHash" TEXT NOT NULL,
    "bundle" JSONB NOT NULL DEFAULT '{}',
    "generatedBy" TEXT NOT NULL,
    "generatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "downloadCount" INTEGER NOT NULL DEFAULT 0,
    "lastDownloadAt" TIMESTAMP(3),

    CONSTRAINT "AuditEvidencePackage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditorAccessGrant" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "assessmentIds" JSONB NOT NULL DEFAULT '[]',
    "evidenceIds" JSONB NOT NULL DEFAULT '[]',
    "grantedBy" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditorAccessGrant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingControlLink" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "confidence" TEXT NOT NULL,
    "origin" TEXT NOT NULL DEFAULT 'AUTOMATIC',
    "ruleId" TEXT,
    "rationale" TEXT NOT NULL DEFAULT '',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FindingControlLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ThirdPartyVendor" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "criticality" TEXT NOT NULL DEFAULT 'MEDIUM',
    "serviceDescription" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "reviewDate" TIMESTAMP(3),
    "riskRating" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ThirdPartyVendor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VendorRiskAssessment" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "vendorId" TEXT NOT NULL,
    "method" TEXT NOT NULL DEFAULT 'QUESTIONNAIRE',
    "riskRating" TEXT NOT NULL,
    "findings" TEXT NOT NULL DEFAULT '',
    "treatment" TEXT NOT NULL DEFAULT '',
    "evidenceIds" JSONB NOT NULL DEFAULT '[]',
    "assessedBy" TEXT NOT NULL,
    "assessedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VendorRiskAssessment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GrcReportSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "reportType" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "content" JSONB NOT NULL DEFAULT '{}',
    "contentHash" TEXT NOT NULL,
    "generatedBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GrcReportSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GrcRetentionPolicy" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assessmentRetentionDays" INTEGER NOT NULL DEFAULT 2555,
    "evidenceRetentionDays" INTEGER NOT NULL DEFAULT 2555,
    "packageRetentionDays" INTEGER NOT NULL DEFAULT 2555,
    "riskRetentionDays" INTEGER NOT NULL DEFAULT 2555,
    "auditRetentionDays" INTEGER NOT NULL DEFAULT 2555,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GrcRetentionPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ComplianceRequirement_frameworkId_idx" ON "ComplianceRequirement"("frameworkId");

-- CreateIndex
CREATE UNIQUE INDEX "ComplianceRequirement_frameworkId_requirementId_key" ON "ComplianceRequirement"("frameworkId", "requirementId");

-- CreateIndex
CREATE INDEX "SecurityControl_workspaceId_idx" ON "SecurityControl"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityControl_workspaceId_code_key" ON "SecurityControl"("workspaceId", "code");

-- CreateIndex
CREATE INDEX "ControlOwner_workspaceId_controlId_idx" ON "ControlOwner"("workspaceId", "controlId");

-- CreateIndex
CREATE INDEX "ControlFrameworkMapping_workspaceId_requirementId_idx" ON "ControlFrameworkMapping"("workspaceId", "requirementId");

-- CreateIndex
CREATE INDEX "ControlFrameworkMapping_workspaceId_controlId_idx" ON "ControlFrameworkMapping"("workspaceId", "controlId");

-- CreateIndex
CREATE UNIQUE INDEX "ControlFrameworkMapping_workspaceId_controlId_requirementId_key" ON "ControlFrameworkMapping"("workspaceId", "controlId", "requirementId");

-- CreateIndex
CREATE INDEX "ControlTest_workspaceId_controlId_idx" ON "ControlTest"("workspaceId", "controlId");

-- CreateIndex
CREATE INDEX "ControlSignal_workspaceId_controlId_signalKey_idx" ON "ControlSignal"("workspaceId", "controlId", "signalKey");

-- CreateIndex
CREATE INDEX "ControlSignal_workspaceId_observedAt_idx" ON "ControlSignal"("workspaceId", "observedAt");

-- CreateIndex
CREATE INDEX "ControlEvaluation_workspaceId_controlId_idx" ON "ControlEvaluation"("workspaceId", "controlId");

-- CreateIndex
CREATE INDEX "ControlEvaluation_workspaceId_evaluatedAt_idx" ON "ControlEvaluation"("workspaceId", "evaluatedAt");

-- CreateIndex
CREATE INDEX "ComplianceEvidence_workspaceId_controlId_idx" ON "ComplianceEvidence"("workspaceId", "controlId");

-- CreateIndex
CREATE INDEX "ComplianceEvidence_workspaceId_status_idx" ON "ComplianceEvidence"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "ComplianceEvidence_workspaceId_collectedAt_idx" ON "ComplianceEvidence"("workspaceId", "collectedAt");

-- CreateIndex
CREATE INDEX "EvidenceFreshnessPolicy_workspaceId_idx" ON "EvidenceFreshnessPolicy"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "EvidenceFreshnessPolicy_workspaceId_controlId_key" ON "EvidenceFreshnessPolicy"("workspaceId", "controlId");

-- CreateIndex
CREATE INDEX "ComplianceAssessment_workspaceId_frameworkId_idx" ON "ComplianceAssessment"("workspaceId", "frameworkId");

-- CreateIndex
CREATE INDEX "ComplianceAssessment_workspaceId_status_idx" ON "ComplianceAssessment"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AssessmentRequirementResult_workspaceId_assessmentId_idx" ON "AssessmentRequirementResult"("workspaceId", "assessmentId");

-- CreateIndex
CREATE UNIQUE INDEX "AssessmentRequirementResult_assessmentId_requirementId_key" ON "AssessmentRequirementResult"("assessmentId", "requirementId");

-- CreateIndex
CREATE INDEX "ComplianceDriftEvent_workspaceId_controlId_idx" ON "ComplianceDriftEvent"("workspaceId", "controlId");

-- CreateIndex
CREATE INDEX "ComplianceDriftEvent_workspaceId_createdAt_idx" ON "ComplianceDriftEvent"("workspaceId", "createdAt");

-- CreateIndex
CREATE INDEX "ControlTestSchedule_workspaceId_controlId_idx" ON "ControlTestSchedule"("workspaceId", "controlId");

-- CreateIndex
CREATE UNIQUE INDEX "RiskRegister_workspaceId_key" ON "RiskRegister"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "RiskMatrix_workspaceId_key" ON "RiskMatrix"("workspaceId");

-- CreateIndex
CREATE INDEX "RiskRecord_workspaceId_status_idx" ON "RiskRecord"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RiskRecord_workspaceId_ownerId_idx" ON "RiskRecord"("workspaceId", "ownerId");

-- CreateIndex
CREATE INDEX "RiskLink_workspaceId_riskId_idx" ON "RiskLink"("workspaceId", "riskId");

-- CreateIndex
CREATE UNIQUE INDEX "RiskLink_riskId_linkType_linkId_key" ON "RiskLink"("riskId", "linkType", "linkId");

-- CreateIndex
CREATE INDEX "RiskTreatmentPlan_workspaceId_riskId_idx" ON "RiskTreatmentPlan"("workspaceId", "riskId");

-- CreateIndex
CREATE INDEX "RiskTreatmentAction_workspaceId_planId_idx" ON "RiskTreatmentAction"("workspaceId", "planId");

-- CreateIndex
CREATE INDEX "RiskTreatmentAction_workspaceId_status_idx" ON "RiskTreatmentAction"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RiskAcceptance_workspaceId_riskId_idx" ON "RiskAcceptance"("workspaceId", "riskId");

-- CreateIndex
CREATE INDEX "RiskAcceptance_workspaceId_status_idx" ON "RiskAcceptance"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "RiskAcceptance_expiresAt_idx" ON "RiskAcceptance"("expiresAt");

-- CreateIndex
CREATE INDEX "RiskReview_workspaceId_riskId_idx" ON "RiskReview"("workspaceId", "riskId");

-- CreateIndex
CREATE INDEX "GovernancePolicy_workspaceId_status_idx" ON "GovernancePolicy"("workspaceId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "GovernancePolicy_workspaceId_title_version_key" ON "GovernancePolicy"("workspaceId", "title", "version");

-- CreateIndex
CREATE INDEX "PolicyAcknowledgement_workspaceId_userId_idx" ON "PolicyAcknowledgement"("workspaceId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "PolicyAcknowledgement_policyId_userId_key" ON "PolicyAcknowledgement"("policyId", "userId");

-- CreateIndex
CREATE INDEX "AuditEngagement_workspaceId_status_idx" ON "AuditEngagement"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AuditEvidenceRequest_workspaceId_auditId_idx" ON "AuditEvidenceRequest"("workspaceId", "auditId");

-- CreateIndex
CREATE INDEX "AuditEvidenceRequest_workspaceId_status_idx" ON "AuditEvidenceRequest"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AuditFinding_workspaceId_auditId_idx" ON "AuditFinding"("workspaceId", "auditId");

-- CreateIndex
CREATE INDEX "AuditFinding_workspaceId_status_idx" ON "AuditFinding"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "AuditEvidencePackage_workspaceId_auditId_idx" ON "AuditEvidencePackage"("workspaceId", "auditId");

-- CreateIndex
CREATE INDEX "AuditorAccessGrant_workspaceId_userId_idx" ON "AuditorAccessGrant"("workspaceId", "userId");

-- CreateIndex
CREATE INDEX "AuditorAccessGrant_expiresAt_idx" ON "AuditorAccessGrant"("expiresAt");

-- CreateIndex
CREATE INDEX "FindingControlLink_workspaceId_controlId_idx" ON "FindingControlLink"("workspaceId", "controlId");

-- CreateIndex
CREATE UNIQUE INDEX "FindingControlLink_workspaceId_findingId_key" ON "FindingControlLink"("workspaceId", "findingId");

-- CreateIndex
CREATE INDEX "ThirdPartyVendor_workspaceId_status_idx" ON "ThirdPartyVendor"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "VendorRiskAssessment_workspaceId_vendorId_idx" ON "VendorRiskAssessment"("workspaceId", "vendorId");

-- CreateIndex
CREATE INDEX "GrcReportSnapshot_workspaceId_reportType_idx" ON "GrcReportSnapshot"("workspaceId", "reportType");

-- CreateIndex
CREATE INDEX "GrcReportSnapshot_workspaceId_createdAt_idx" ON "GrcReportSnapshot"("workspaceId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "GrcRetentionPolicy_workspaceId_key" ON "GrcRetentionPolicy"("workspaceId");

-- CreateIndex
CREATE INDEX "ComplianceFramework_status_idx" ON "ComplianceFramework"("status");

-- CreateIndex
CREATE UNIQUE INDEX "ComplianceFramework_key_version_key" ON "ComplianceFramework"("key", "version");

-- AddForeignKey
ALTER TABLE "ComplianceRequirement" ADD CONSTRAINT "ComplianceRequirement_frameworkId_fkey" FOREIGN KEY ("frameworkId") REFERENCES "ComplianceFramework"("id") ON DELETE CASCADE ON UPDATE CASCADE;

