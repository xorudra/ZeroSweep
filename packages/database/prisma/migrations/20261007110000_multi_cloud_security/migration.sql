-- CreateEnum
CREATE TYPE "CloudProvider" AS ENUM ('AWS', 'AZURE', 'GCP');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssessmentProfile" ADD VALUE 'CLOUD_INVENTORY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'CLOUD_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'CLOUD_COMPREHENSIVE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'IAM_REVIEW';
ALTER TYPE "AssessmentProfile" ADD VALUE 'PUBLIC_EXPOSURE_REVIEW';
ALTER TYPE "AssessmentProfile" ADD VALUE 'COMPLIANCE_ASSESSMENT';
ALTER TYPE "AssessmentProfile" ADD VALUE 'IAC_TO_CLOUD_CORRELATION';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'CLOUD_AUTH';
ALTER TYPE "ScanStageType" ADD VALUE 'CLOUD_INVENTORY';
ALTER TYPE "ScanStageType" ADD VALUE 'IAM_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'NETWORK_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'STORAGE_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'ENCRYPTION_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'LOGGING_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'CLOUD_CSPM';
ALTER TYPE "ScanStageType" ADD VALUE 'CLOUD_COMPLIANCE';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_ACCOUNT_REGISTERED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_CREDENTIAL_VALIDATED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_RESOURCE_DISCOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'PUBLIC_EXPOSURE_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'IAM_RISK_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_DRIFT_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_COMPLIANCE_ASSESSED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_ARTIFACT_ACCESSED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "cloudAccountId" TEXT,
ADD COLUMN     "cloudProvider" TEXT,
ADD COLUMN     "cloudRegion" TEXT,
ADD COLUMN     "cloudResourceId" TEXT,
ADD COLUMN     "findingClass" TEXT,
ADD COLUMN     "providerResourceId" TEXT;

-- AlterTable
ALTER TABLE "ContainerRegistry" ADD COLUMN     "cloudAccountId" TEXT,
ADD COLUMN     "cloudResourceId" TEXT;

-- AlterTable
ALTER TABLE "KubernetesCluster" ADD COLUMN     "cloudAccountId" TEXT,
ADD COLUMN     "cloudResourceId" TEXT;

-- CreateTable
CREATE TABLE "CloudAccount" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "provider" "CloudProvider" NOT NULL,
    "name" TEXT NOT NULL,
    "externalAccountId" TEXT NOT NULL,
    "environment" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'MEDIUM',
    "credentialReference" TEXT,
    "assessmentPolicy" TEXT NOT NULL DEFAULT 'READ_ONLY',
    "status" TEXT NOT NULL DEFAULT 'REGISTERED',
    "identityMetadata" JSONB,
    "lastInventoryAt" TIMESTAMP(3),
    "lastAssessmentAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CloudAccount_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudScope" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "includeRegions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "excludeRegions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "includeUnits" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "excludeUnits" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "includeResources" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "excludeResources" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CloudScope_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudResource" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "provider" "CloudProvider" NOT NULL,
    "resourceType" TEXT NOT NULL,
    "providerResourceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "region" TEXT,
    "zone" TEXT,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "configurationMetadata" JSONB NOT NULL DEFAULT '{}',
    "exposure" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'UNSPECIFIED',
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "scopeStatus" TEXT NOT NULL DEFAULT 'IN_SCOPE',
    "sources" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CloudResource_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudInventorySnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "scanId" TEXT,
    "provider" "CloudProvider" NOT NULL,
    "regions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "resourceCounts" JSONB NOT NULL DEFAULT '{}',
    "snapshotHash" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CloudInventorySnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudIdentity" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "provider" "CloudProvider" NOT NULL,
    "identityType" TEXT NOT NULL,
    "providerIdentityId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "privileged" BOOLEAN NOT NULL DEFAULT false,
    "privilegeEvidence" JSONB,
    "mfaEnabled" BOOLEAN,
    "lastUsedAt" TIMESTAMP(3),
    "lastSignInAt" TIMESTAMP(3),
    "keyAgeDays" INTEGER,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CloudIdentity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudRelationship" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "fromType" TEXT NOT NULL,
    "fromRef" TEXT NOT NULL,
    "toType" TEXT NOT NULL,
    "toRef" TEXT NOT NULL,
    "relationship" TEXT NOT NULL,
    "evidence" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CloudRelationship_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudRiskPath" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "scanId" TEXT,
    "title" TEXT NOT NULL,
    "steps" JSONB NOT NULL DEFAULT '[]',
    "confidence" TEXT NOT NULL DEFAULT 'LOW',
    "findingIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CloudRiskPath_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudDriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "scanId" TEXT,
    "snapshotId" TEXT,
    "kind" TEXT NOT NULL,
    "state" TEXT,
    "resourceRef" TEXT,
    "detail" TEXT NOT NULL DEFAULT '',
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CloudDriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CredentialLease" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "scanId" TEXT,
    "credentialReference" TEXT NOT NULL,
    "purpose" TEXT NOT NULL DEFAULT 'CLOUD_ASSESSMENT',
    "status" TEXT NOT NULL DEFAULT 'ISSUED',
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "releasedAt" TIMESTAMP(3),

    CONSTRAINT "CredentialLease_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CloudAccount_workspaceId_idx" ON "CloudAccount"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudAccount_workspaceId_provider_idx" ON "CloudAccount"("workspaceId", "provider");

-- CreateIndex
CREATE UNIQUE INDEX "CloudAccount_workspaceId_provider_externalAccountId_key" ON "CloudAccount"("workspaceId", "provider", "externalAccountId");

-- CreateIndex
CREATE INDEX "CloudScope_workspaceId_idx" ON "CloudScope"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudScope_cloudAccountId_idx" ON "CloudScope"("cloudAccountId");

-- CreateIndex
CREATE INDEX "CloudResource_workspaceId_idx" ON "CloudResource"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudResource_cloudAccountId_resourceType_idx" ON "CloudResource"("cloudAccountId", "resourceType");

-- CreateIndex
CREATE INDEX "CloudResource_workspaceId_exposure_idx" ON "CloudResource"("workspaceId", "exposure");

-- CreateIndex
CREATE UNIQUE INDEX "CloudResource_cloudAccountId_providerResourceId_key" ON "CloudResource"("cloudAccountId", "providerResourceId");

-- CreateIndex
CREATE INDEX "CloudInventorySnapshot_workspaceId_idx" ON "CloudInventorySnapshot"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudInventorySnapshot_cloudAccountId_idx" ON "CloudInventorySnapshot"("cloudAccountId");

-- CreateIndex
CREATE INDEX "CloudInventorySnapshot_scanId_idx" ON "CloudInventorySnapshot"("scanId");

-- CreateIndex
CREATE INDEX "CloudIdentity_workspaceId_idx" ON "CloudIdentity"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudIdentity_cloudAccountId_identityType_idx" ON "CloudIdentity"("cloudAccountId", "identityType");

-- CreateIndex
CREATE UNIQUE INDEX "CloudIdentity_cloudAccountId_providerIdentityId_key" ON "CloudIdentity"("cloudAccountId", "providerIdentityId");

-- CreateIndex
CREATE INDEX "CloudRelationship_workspaceId_idx" ON "CloudRelationship"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudRelationship_cloudAccountId_idx" ON "CloudRelationship"("cloudAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "CloudRelationship_cloudAccountId_fromType_fromRef_relations_key" ON "CloudRelationship"("cloudAccountId", "fromType", "fromRef", "relationship", "toType", "toRef");

-- CreateIndex
CREATE INDEX "CloudRiskPath_workspaceId_idx" ON "CloudRiskPath"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudRiskPath_cloudAccountId_idx" ON "CloudRiskPath"("cloudAccountId");

-- CreateIndex
CREATE INDEX "CloudDriftEvent_workspaceId_idx" ON "CloudDriftEvent"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudDriftEvent_cloudAccountId_idx" ON "CloudDriftEvent"("cloudAccountId");

-- CreateIndex
CREATE INDEX "CloudDriftEvent_kind_idx" ON "CloudDriftEvent"("kind");

-- CreateIndex
CREATE INDEX "CredentialLease_workspaceId_idx" ON "CredentialLease"("workspaceId");

-- CreateIndex
CREATE INDEX "CredentialLease_cloudAccountId_idx" ON "CredentialLease"("cloudAccountId");

-- CreateIndex
CREATE INDEX "CredentialLease_scanId_idx" ON "CredentialLease"("scanId");

-- CreateIndex
CREATE INDEX "Finding_cloudAccountId_idx" ON "Finding"("cloudAccountId");

-- CreateIndex
CREATE INDEX "Finding_cloudResourceId_idx" ON "Finding"("cloudResourceId");

-- CreateIndex
CREATE INDEX "Finding_providerResourceId_idx" ON "Finding"("providerResourceId");

-- AddForeignKey
ALTER TABLE "CloudScope" ADD CONSTRAINT "CloudScope_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CloudResource" ADD CONSTRAINT "CloudResource_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CloudInventorySnapshot" ADD CONSTRAINT "CloudInventorySnapshot_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CloudIdentity" ADD CONSTRAINT "CloudIdentity_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CloudRelationship" ADD CONSTRAINT "CloudRelationship_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CloudRiskPath" ADD CONSTRAINT "CloudRiskPath_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CloudDriftEvent" ADD CONSTRAINT "CloudDriftEvent_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CredentialLease" ADD CONSTRAINT "CredentialLease_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;
