-- CreateEnum
CREATE TYPE "ScannerDeploymentType" AS ENUM ('MANAGED_DAEMON', 'ADMIN_PROVIDED', 'IMPORT_ONLY');

-- CreateEnum
CREATE TYPE "ScannerHealthStatus" AS ENUM ('NOT_CONFIGURED', 'HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'MISCONFIGURED');

-- CreateEnum
CREATE TYPE "SessionProfileType" AS ENUM ('ANONYMOUS', 'AUTHENTICATED', 'API_AUTHENTICATED');

-- CreateEnum
CREATE TYPE "AuthenticationMode" AS ENUM ('FORM', 'BASIC', 'BEARER', 'API_KEY', 'COOKIE', 'OAUTH', 'CUSTOM_HEADER');

-- CreateEnum
CREATE TYPE "ScanApprovalStatus" AS ENUM ('ACTIVE', 'EXPIRED', 'REVOKED', 'INVALIDATED');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'PASSIVE_SECURITY_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'ACTIVE_SECURITY_ANALYSIS';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'SCANNER_CONTEXT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCANNER_CONTEXT_DESTROYED';
ALTER TYPE "AuditAction" ADD VALUE 'PASSIVE_ANALYSIS_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'PASSIVE_ANALYSIS_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'AUTH_SESSION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'AUTH_SESSION_EXPIRED';
ALTER TYPE "AuditAction" ADD VALUE 'ACTIVE_SCAN_APPROVAL_GRANTED';
ALTER TYPE "AuditAction" ADD VALUE 'ACTIVE_SCAN_APPROVAL_REVOKED';
ALTER TYPE "AuditAction" ADD VALUE 'ACTIVE_SCAN_DENIED';
ALTER TYPE "AuditAction" ADD VALUE 'RAW_EVIDENCE_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'SCANNER_INSTANCE_REGISTERED';
ALTER TYPE "AuditAction" ADD VALUE 'SCANNER_INSTANCE_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCANNER_IMPORT_COMPLETED';

-- CreateTable
CREATE TABLE "ScannerInstance" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT,
    "toolId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "endpointReference" TEXT NOT NULL,
    "deploymentType" "ScannerDeploymentType" NOT NULL DEFAULT 'MANAGED_DAEMON',
    "credentialReference" TEXT,
    "declaredCapabilities" JSONB NOT NULL DEFAULT '[]',
    "detectedCapabilities" JSONB NOT NULL DEFAULT '[]',
    "healthStatus" "ScannerHealthStatus" NOT NULL DEFAULT 'NOT_CONFIGURED',
    "version" TEXT,
    "licenseState" TEXT,
    "lastHealthCheckAt" TIMESTAMP(3),
    "lastHealthDetail" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScannerInstance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SessionProfile" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "SessionProfileType" NOT NULL DEFAULT 'ANONYMOUS',
    "credentialReference" TEXT,
    "cookiePolicy" JSONB,
    "headerPolicy" JSONB,
    "validation" JSONB,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SessionProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthenticationProfile" (
    "id" TEXT NOT NULL,
    "sessionProfileId" TEXT NOT NULL,
    "mode" "AuthenticationMode" NOT NULL,
    "loginUrl" TEXT,
    "usernameField" TEXT,
    "passwordField" TEXT,
    "tokenHeaderName" TEXT,
    "credentialReference" TEXT,
    "config" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuthenticationProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HttpTransaction" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT,
    "endpointId" TEXT,
    "toolExecutionId" TEXT,
    "method" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "statusCode" INTEGER,
    "source" TEXT NOT NULL,
    "scopeStatus" TEXT NOT NULL DEFAULT 'IN_SCOPE',
    "apiKind" TEXT,
    "requestHash" TEXT,
    "responseHash" TEXT,
    "requestSize" INTEGER,
    "responseSize" INTEGER,
    "requestArtifactRef" TEXT,
    "responseArtifactRef" TEXT,
    "requestRedacted" TEXT,
    "responseRedacted" TEXT,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "HttpTransaction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebSocketEndpoint" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "origin" TEXT,
    "subprotocol" TEXT,
    "source" TEXT NOT NULL,
    "scopeStatus" TEXT NOT NULL DEFAULT 'IN_SCOPE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WebSocketEndpoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanApproval" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assessmentId" TEXT NOT NULL,
    "scanId" TEXT,
    "capability" TEXT NOT NULL,
    "scannerInstanceId" TEXT,
    "scopeId" TEXT,
    "scopeSnapshot" JSONB NOT NULL,
    "scopeSnapshotHash" TEXT NOT NULL,
    "policySnapshot" JSONB,
    "status" "ScanApprovalStatus" NOT NULL DEFAULT 'ACTIVE',
    "approvedBy" TEXT NOT NULL,
    "approvedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedBy" TEXT,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanApproval_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ScannerInstance_organizationId_idx" ON "ScannerInstance"("organizationId");

-- CreateIndex
CREATE INDEX "ScannerInstance_workspaceId_idx" ON "ScannerInstance"("workspaceId");

-- CreateIndex
CREATE INDEX "ScannerInstance_toolId_idx" ON "ScannerInstance"("toolId");

-- CreateIndex
CREATE INDEX "SessionProfile_workspaceId_idx" ON "SessionProfile"("workspaceId");

-- CreateIndex
CREATE INDEX "AuthenticationProfile_sessionProfileId_idx" ON "AuthenticationProfile"("sessionProfileId");

-- CreateIndex
CREATE INDEX "HttpTransaction_scanId_idx" ON "HttpTransaction"("scanId");

-- CreateIndex
CREATE INDEX "HttpTransaction_workspaceId_idx" ON "HttpTransaction"("workspaceId");

-- CreateIndex
CREATE INDEX "HttpTransaction_host_idx" ON "HttpTransaction"("host");

-- CreateIndex
CREATE INDEX "WebSocketEndpoint_scanId_idx" ON "WebSocketEndpoint"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "WebSocketEndpoint_scanId_url_key" ON "WebSocketEndpoint"("scanId", "url");

-- CreateIndex
CREATE INDEX "ScanApproval_workspaceId_idx" ON "ScanApproval"("workspaceId");

-- CreateIndex
CREATE INDEX "ScanApproval_assessmentId_idx" ON "ScanApproval"("assessmentId");

-- CreateIndex
CREATE INDEX "ScanApproval_scanId_idx" ON "ScanApproval"("scanId");

-- AddForeignKey
ALTER TABLE "ScannerInstance" ADD CONSTRAINT "ScannerInstance_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScannerInstance" ADD CONSTRAINT "ScannerInstance_toolId_fkey" FOREIGN KEY ("toolId") REFERENCES "Tool"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SessionProfile" ADD CONSTRAINT "SessionProfile_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthenticationProfile" ADD CONSTRAINT "AuthenticationProfile_sessionProfileId_fkey" FOREIGN KEY ("sessionProfileId") REFERENCES "SessionProfile"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "HttpTransaction" ADD CONSTRAINT "HttpTransaction_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WebSocketEndpoint" ADD CONSTRAINT "WebSocketEndpoint_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanApproval" ADD CONSTRAINT "ScanApproval_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanApproval" ADD CONSTRAINT "ScanApproval_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

