-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_TARGET_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_PREFLIGHT_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_SCAN_PLANNED';
ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_SCAN_CANCELLED';
ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_SCAN_PARTIAL';
ALTER TYPE "AuditAction" ADD VALUE 'AUTH_PROFILE_USED';
ALTER TYPE "AuditAction" ADD VALUE 'HIGH_RISK_TEST_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_FINDING_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'WEB_VAPT_FINDING_VERIFIED';

-- CreateTable
CREATE TABLE "WebVaptTarget" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "baseUrl" TEXT NOT NULL,
    "normalizedOrigin" TEXT NOT NULL,
    "authorizationId" TEXT NOT NULL,
    "environment" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'MEDIUM',
    "authenticationProfileId" TEXT,
    "scanProfileKey" TEXT NOT NULL DEFAULT 'WEB_SAFE',
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WebVaptTarget_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanScopeSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "planId" TEXT,
    "scanId" TEXT,
    "origins" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "hosts" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "exclusions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "hash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanScopeSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebVaptScanPlan" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "webTargetId" TEXT NOT NULL,
    "scanId" TEXT,
    "profileKey" TEXT NOT NULL,
    "stages" JSONB NOT NULL DEFAULT '[]',
    "allowedTools" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "blockedModules" JSONB NOT NULL DEFAULT '[]',
    "budget" JSONB NOT NULL,
    "estimatedRequestClass" TEXT NOT NULL DEFAULT 'MEDIUM',
    "scopeSnapshotId" TEXT NOT NULL,
    "authenticationProfileId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'PLANNED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WebVaptScanPlan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebVaptPreflightResult" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "webTargetId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "checks" JSONB NOT NULL DEFAULT '[]',
    "redirectRecorded" TEXT,
    "probeTransport" TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WebVaptPreflightResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiSpecificationSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "specificationId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "version" TEXT,
    "hash" TEXT NOT NULL,
    "endpointCount" INTEGER NOT NULL DEFAULT 0,
    "schemaCount" INTEGER NOT NULL DEFAULT 0,
    "rejectedHosts" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "importedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ApiSpecificationSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthorizationMatrixEntry" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "testCaseId" TEXT NOT NULL,
    "identityA" TEXT NOT NULL,
    "identityB" TEXT,
    "role" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "expectedAccess" TEXT NOT NULL,
    "observedAccess" TEXT NOT NULL DEFAULT 'NOT_TESTED',
    "result" TEXT NOT NULL DEFAULT 'NOT_TESTED',
    "candidateFinding" JSONB,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuthorizationMatrixEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BusinessLogicScenario" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "preconditions" TEXT NOT NULL DEFAULT '',
    "authorizedIdentities" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "safeSteps" JSONB NOT NULL DEFAULT '[]',
    "expectedBehavior" TEXT NOT NULL,
    "observedBehavior" TEXT,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BusinessLogicScenario_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebScanSession" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "authenticationProfileId" TEXT,
    "credentialReference" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "redactedSummary" JSONB NOT NULL DEFAULT '{}',
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WebScanSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebVaptEvidence" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT,
    "findingId" TEXT,
    "kind" TEXT NOT NULL,
    "sanitizedRequest" TEXT,
    "sanitizedResponse" TEXT,
    "marker" TEXT,
    "artifactRef" TEXT,
    "sizeBytes" INTEGER NOT NULL DEFAULT 0,
    "sha256" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WebVaptEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebVaptCoverage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "discoveredEndpoints" INTEGER NOT NULL DEFAULT 0,
    "testedEndpoints" INTEGER NOT NULL DEFAULT 0,
    "endpointCoverage" DOUBLE PRECISION,
    "parameterCoverage" DOUBLE PRECISION,
    "authenticatedCoverage" DOUBLE PRECISION,
    "toolCoverage" JSONB NOT NULL DEFAULT '{}',
    "skipped" JSONB NOT NULL DEFAULT '[]',
    "limitations" JSONB NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WebVaptCoverage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebToolHealth" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "installed" BOOLEAN NOT NULL DEFAULT false,
    "version" TEXT,
    "lastSuccessfulRun" TIMESTAMP(3),
    "errorRate" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "parserCompatible" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WebToolHealth_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "WebVaptTarget_workspaceId_status_idx" ON "WebVaptTarget"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "WebVaptTarget_assetId_idx" ON "WebVaptTarget"("assetId");

-- CreateIndex
CREATE INDEX "ScanScopeSnapshot_workspaceId_idx" ON "ScanScopeSnapshot"("workspaceId");

-- CreateIndex
CREATE INDEX "ScanScopeSnapshot_hash_idx" ON "ScanScopeSnapshot"("hash");

-- CreateIndex
CREATE INDEX "WebVaptScanPlan_workspaceId_status_idx" ON "WebVaptScanPlan"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "WebVaptScanPlan_webTargetId_idx" ON "WebVaptScanPlan"("webTargetId");

-- CreateIndex
CREATE INDEX "WebVaptPreflightResult_workspaceId_webTargetId_idx" ON "WebVaptPreflightResult"("workspaceId", "webTargetId");

-- CreateIndex
CREATE INDEX "ApiSpecificationSnapshot_workspaceId_idx" ON "ApiSpecificationSnapshot"("workspaceId");

-- CreateIndex
CREATE INDEX "ApiSpecificationSnapshot_specificationId_idx" ON "ApiSpecificationSnapshot"("specificationId");

-- CreateIndex
CREATE INDEX "AuthorizationMatrixEntry_workspaceId_testCaseId_idx" ON "AuthorizationMatrixEntry"("workspaceId", "testCaseId");

-- CreateIndex
CREATE INDEX "BusinessLogicScenario_workspaceId_status_idx" ON "BusinessLogicScenario"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "WebScanSession_workspaceId_scanId_idx" ON "WebScanSession"("workspaceId", "scanId");

-- CreateIndex
CREATE INDEX "WebVaptEvidence_workspaceId_scanId_idx" ON "WebVaptEvidence"("workspaceId", "scanId");

-- CreateIndex
CREATE INDEX "WebVaptEvidence_findingId_idx" ON "WebVaptEvidence"("findingId");

-- CreateIndex
CREATE UNIQUE INDEX "WebVaptCoverage_scanId_key" ON "WebVaptCoverage"("scanId");

-- CreateIndex
CREATE INDEX "WebVaptCoverage_workspaceId_idx" ON "WebVaptCoverage"("workspaceId");

-- CreateIndex
CREATE INDEX "WebToolHealth_workspaceId_idx" ON "WebToolHealth"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "WebToolHealth_workspaceId_slug_key" ON "WebToolHealth"("workspaceId", "slug");
