-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_TARGET_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_PREFLIGHT_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_SCAN_PLANNED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_SCAN_PARTIAL';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_SCAN_CANCELLED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_HOST_DISCOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_SERVICE_DISCOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_VULNERABILITY_FOUND';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_VULNERABILITY_VERIFIED';
ALTER TYPE "AuditAction" ADD VALUE 'NETWORK_DRIFT_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'PACKET_CAPTURE_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'PACKET_CAPTURE_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTROLLED_METASPLOIT_VERIFICATION_REQUESTED';

-- CreateTable
CREATE TABLE "NetworkVaptTarget" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetValue" TEXT NOT NULL,
    "authorizationId" TEXT NOT NULL,
    "environment" TEXT NOT NULL DEFAULT 'PRODUCTION',
    "criticality" TEXT NOT NULL DEFAULT 'UNSPECIFIED',
    "scanProfileId" TEXT NOT NULL DEFAULT 'NETWORK_SAFE',
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NetworkVaptTarget_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkVaptPreflightResult" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "checks" JSONB NOT NULL DEFAULT '[]',
    "probeTransport" TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "NetworkVaptPreflightResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkVaptScanPlan" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "scanId" TEXT,
    "profile" TEXT NOT NULL,
    "stages" JSONB NOT NULL DEFAULT '[]',
    "tools" JSONB NOT NULL DEFAULT '[]',
    "portPolicy" JSONB NOT NULL DEFAULT '{}',
    "rateLimits" JSONB NOT NULL DEFAULT '{}',
    "timeouts" JSONB NOT NULL DEFAULT '{}',
    "serviceDetection" BOOLEAN NOT NULL DEFAULT true,
    "vulnerabilityScanners" JSONB NOT NULL DEFAULT '[]',
    "verificationPolicy" JSONB NOT NULL DEFAULT '{}',
    "estimatedWorkloadClass" TEXT NOT NULL DEFAULT 'SMALL',
    "budget" JSONB NOT NULL DEFAULT '{}',
    "scopeSnapshotId" TEXT,
    "scriptsUsed" JSONB NOT NULL DEFAULT '[]',
    "blockedItems" JSONB NOT NULL DEFAULT '[]',
    "status" TEXT NOT NULL DEFAULT 'PLANNED',
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NetworkVaptScanPlan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkHostObservation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT,
    "ip" TEXT NOT NULL,
    "hostname" TEXT,
    "macAddress" TEXT,
    "vendorHint" TEXT,
    "discoveryMethod" TEXT NOT NULL,
    "hostStatus" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "scopeStatus" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NetworkHostObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OsFingerprintObservation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT,
    "host" TEXT NOT NULL,
    "family" TEXT NOT NULL,
    "versionHint" TEXT,
    "confidence" DOUBLE PRECISION NOT NULL,
    "band" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OsFingerprintObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkSegment" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "cidr" TEXT NOT NULL,
    "environment" TEXT NOT NULL DEFAULT 'PRODUCTION',
    "zone" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'MEDIUM',
    "owner" TEXT,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NetworkSegment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkBaseline" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "segmentId" TEXT,
    "version" INTEGER NOT NULL,
    "hosts" JSONB NOT NULL DEFAULT '[]',
    "hash" TEXT NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "NetworkBaseline_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkDriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "baselineId" TEXT,
    "host" TEXT NOT NULL,
    "assetId" TEXT,
    "kind" TEXT NOT NULL,
    "detail" TEXT NOT NULL,
    "riskSignal" TEXT NOT NULL DEFAULT 'STANDARD',
    "signalReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "NetworkDriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkVaptCoverage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "authorizedHosts" INTEGER NOT NULL DEFAULT 0,
    "discoveredHosts" INTEGER NOT NULL DEFAULT 0,
    "scannedHosts" INTEGER NOT NULL DEFAULT 0,
    "portCoverage" DOUBLE PRECISION,
    "serviceCoverage" DOUBLE PRECISION,
    "vulnScannerCoverage" DOUBLE PRECISION,
    "credentialedCoverage" DOUBLE PRECISION,
    "limitations" JSONB NOT NULL DEFAULT '[]',
    "completion" TEXT NOT NULL DEFAULT 'COMPLETED_WITH_GAPS',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NetworkVaptCoverage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkPacketCaptureJob" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "scanId" TEXT,
    "interfaceReference" TEXT NOT NULL,
    "filter" TEXT,
    "durationSeconds" INTEGER NOT NULL,
    "sizeLimitBytes" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'REQUESTED',
    "evidenceRef" TEXT,
    "summary" JSONB NOT NULL DEFAULT '{}',
    "transport" TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
    "createdById" TEXT,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NetworkPacketCaptureJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DefensiveExploitReference" (
    "id" TEXT NOT NULL,
    "referenceId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "affectedProduct" TEXT NOT NULL,
    "cveIds" JSONB NOT NULL DEFAULT '[]',
    "source" TEXT NOT NULL,
    "referenceUrl" TEXT NOT NULL,
    "publishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DefensiveExploitReference_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MetasploitVerificationRequest" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "findingId" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "moduleId" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "reasons" JSONB NOT NULL DEFAULT '[]',
    "transport" TEXT NOT NULL DEFAULT 'NOT_PROVISIONED',
    "requestedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MetasploitVerificationRequest_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "NetworkVaptTarget_workspaceId_targetType_idx" ON "NetworkVaptTarget"("workspaceId", "targetType");

-- CreateIndex
CREATE INDEX "NetworkVaptTarget_workspaceId_assetId_idx" ON "NetworkVaptTarget"("workspaceId", "assetId");

-- CreateIndex
CREATE INDEX "NetworkVaptPreflightResult_workspaceId_targetId_createdAt_idx" ON "NetworkVaptPreflightResult"("workspaceId", "targetId", "createdAt");

-- CreateIndex
CREATE INDEX "NetworkVaptScanPlan_workspaceId_targetId_createdAt_idx" ON "NetworkVaptScanPlan"("workspaceId", "targetId", "createdAt");

-- CreateIndex
CREATE INDEX "NetworkVaptScanPlan_workspaceId_scanId_idx" ON "NetworkVaptScanPlan"("workspaceId", "scanId");

-- CreateIndex
CREATE INDEX "NetworkHostObservation_workspaceId_scopeStatus_idx" ON "NetworkHostObservation"("workspaceId", "scopeStatus");

-- CreateIndex
CREATE UNIQUE INDEX "NetworkHostObservation_workspaceId_ip_discoveryMethod_key" ON "NetworkHostObservation"("workspaceId", "ip", "discoveryMethod");

-- CreateIndex
CREATE INDEX "OsFingerprintObservation_workspaceId_host_idx" ON "OsFingerprintObservation"("workspaceId", "host");

-- CreateIndex
CREATE INDEX "NetworkSegment_workspaceId_zone_idx" ON "NetworkSegment"("workspaceId", "zone");

-- CreateIndex
CREATE UNIQUE INDEX "NetworkSegment_workspaceId_cidr_key" ON "NetworkSegment"("workspaceId", "cidr");

-- CreateIndex
CREATE INDEX "NetworkBaseline_workspaceId_createdAt_idx" ON "NetworkBaseline"("workspaceId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "NetworkBaseline_workspaceId_segmentId_version_key" ON "NetworkBaseline"("workspaceId", "segmentId", "version");

-- CreateIndex
CREATE INDEX "NetworkDriftEvent_workspaceId_createdAt_idx" ON "NetworkDriftEvent"("workspaceId", "createdAt");

-- CreateIndex
CREATE INDEX "NetworkDriftEvent_workspaceId_host_idx" ON "NetworkDriftEvent"("workspaceId", "host");

-- CreateIndex
CREATE UNIQUE INDEX "NetworkVaptCoverage_scanId_key" ON "NetworkVaptCoverage"("scanId");

-- CreateIndex
CREATE INDEX "NetworkVaptCoverage_workspaceId_idx" ON "NetworkVaptCoverage"("workspaceId");

-- CreateIndex
CREATE INDEX "NetworkPacketCaptureJob_workspaceId_createdAt_idx" ON "NetworkPacketCaptureJob"("workspaceId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "DefensiveExploitReference_referenceId_key" ON "DefensiveExploitReference"("referenceId");

-- CreateIndex
CREATE INDEX "DefensiveExploitReference_affectedProduct_idx" ON "DefensiveExploitReference"("affectedProduct");

-- CreateIndex
CREATE INDEX "MetasploitVerificationRequest_workspaceId_createdAt_idx" ON "MetasploitVerificationRequest"("workspaceId", "createdAt");

