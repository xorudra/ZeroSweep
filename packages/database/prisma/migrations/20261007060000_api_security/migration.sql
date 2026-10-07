-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'API_DISCOVERY';
ALTER TYPE "ScanStageType" ADD VALUE 'SPEC_IMPORT';
ALTER TYPE "ScanStageType" ADD VALUE 'ROUTE_DISCOVERY';
ALTER TYPE "ScanStageType" ADD VALUE 'AUTH_MAPPING';
ALTER TYPE "ScanStageType" ADD VALUE 'SAFE_SCHEMA_TESTING';
ALTER TYPE "ScanStageType" ADD VALUE 'JWT_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'GRAPHQL_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'WEBSOCKET_INVENTORY';
ALTER TYPE "ScanStageType" ADD VALUE 'API_FINDING_NORMALIZATION';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'API_SPEC_IMPORTED';
ALTER TYPE "AuditAction" ADD VALUE 'API_DISCOVERY_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'API_DISCOVERY_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'API_OPERATION_BLOCKED';
ALTER TYPE "AuditAction" ADD VALUE 'JWT_ANALYZED';
ALTER TYPE "AuditAction" ADD VALUE 'GRAPHQL_SCHEMA_IMPORTED';
ALTER TYPE "AuditAction" ADD VALUE 'STATE_CHANGING_OPERATION_DENIED';
ALTER TYPE "AuditAction" ADD VALUE 'API_TEST_COMPLETED';

-- AlterTable
ALTER TABLE "Endpoint" ADD COLUMN     "authRequired" BOOLEAN,
ADD COLUMN     "authSchemes" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "contentTypes" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "operationId" TEXT,
ADD COLUMN     "path" TEXT,
ADD COLUMN     "requestSchemaId" TEXT,
ADD COLUMN     "responseSchemaId" TEXT;

-- AlterTable
ALTER TABLE "WebSocketEndpoint" ADD COLUMN     "authPresent" BOOLEAN;

-- CreateTable
CREATE TABLE "ApiService" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "baseUrl" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "apiType" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "version" TEXT,
    "authenticationType" TEXT,
    "specificationId" TEXT,
    "source" TEXT NOT NULL,
    "scopeStatus" TEXT NOT NULL DEFAULT 'IN_SCOPE',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ApiService_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiSpecification" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "assetId" TEXT,
    "apiServiceId" TEXT,
    "kind" TEXT NOT NULL,
    "version" TEXT,
    "source" TEXT NOT NULL,
    "checksum" TEXT NOT NULL,
    "artifactRef" TEXT,
    "location" TEXT,
    "parsedStatus" TEXT NOT NULL DEFAULT 'PENDING',
    "operationCount" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ApiSpecification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiSchema" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "apiServiceId" TEXT,
    "name" TEXT NOT NULL,
    "schemaType" TEXT NOT NULL,
    "requiredFields" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "properties" JSONB NOT NULL DEFAULT '{}',
    "source" TEXT NOT NULL,
    "artifactRef" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ApiSchema_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GraphqlService" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "assetId" TEXT,
    "endpointUrl" TEXT NOT NULL,
    "schemaAvailable" BOOLEAN NOT NULL DEFAULT false,
    "queries" INTEGER NOT NULL DEFAULT 0,
    "mutations" INTEGER NOT NULL DEFAULT 0,
    "subscriptions" INTEGER NOT NULL DEFAULT 0,
    "types" INTEGER NOT NULL DEFAULT 0,
    "authenticationRequired" BOOLEAN,
    "source" TEXT NOT NULL,
    "scopeStatus" TEXT NOT NULL DEFAULT 'IN_SCOPE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GraphqlService_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "JwtProfile" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT,
    "targetId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "tokenType" TEXT,
    "keyId" TEXT,
    "issuer" TEXT,
    "audience" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "expiresAt" TIMESTAMP(3),
    "notBefore" TIMESTAMP(3),
    "issuedAt" TIMESTAMP(3),
    "lifetimeSeconds" INTEGER,
    "claimsSummary" JSONB NOT NULL DEFAULT '{}',
    "source" TEXT NOT NULL,
    "host" TEXT,
    "endpoint" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "JwtProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiAuthContext" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "apiServiceId" TEXT,
    "role" TEXT NOT NULL,
    "authenticationProfileId" TEXT,
    "sessionProfileId" TEXT,
    "credentialReference" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ApiAuthContext_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthorizationTestCase" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "endpointId" TEXT,
    "objectIdentifier" TEXT,
    "identityAContextId" TEXT,
    "identityBContextId" TEXT,
    "expectedAccess" TEXT,
    "observedAccess" TEXT,
    "approvalStatus" TEXT NOT NULL DEFAULT 'NOT_APPROVED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthorizationTestCase_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TestDataProfile" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "values" JSONB NOT NULL DEFAULT '{}',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TestDataProfile_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ApiService_workspaceId_idx" ON "ApiService"("workspaceId");

-- CreateIndex
CREATE INDEX "ApiService_assetId_idx" ON "ApiService"("assetId");

-- CreateIndex
CREATE UNIQUE INDEX "ApiService_assetId_baseUrl_key" ON "ApiService"("assetId", "baseUrl");

-- CreateIndex
CREATE INDEX "ApiSpecification_workspaceId_idx" ON "ApiSpecification"("workspaceId");

-- CreateIndex
CREATE INDEX "ApiSpecification_targetId_idx" ON "ApiSpecification"("targetId");

-- CreateIndex
CREATE INDEX "ApiSpecification_assetId_idx" ON "ApiSpecification"("assetId");

-- CreateIndex
CREATE INDEX "ApiSchema_workspaceId_idx" ON "ApiSchema"("workspaceId");

-- CreateIndex
CREATE INDEX "ApiSchema_apiServiceId_idx" ON "ApiSchema"("apiServiceId");

-- CreateIndex
CREATE INDEX "GraphqlService_workspaceId_idx" ON "GraphqlService"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "GraphqlService_workspaceId_endpointUrl_key" ON "GraphqlService"("workspaceId", "endpointUrl");

-- CreateIndex
CREATE INDEX "JwtProfile_workspaceId_idx" ON "JwtProfile"("workspaceId");

-- CreateIndex
CREATE INDEX "JwtProfile_scanId_idx" ON "JwtProfile"("scanId");

-- CreateIndex
CREATE INDEX "JwtProfile_fingerprint_idx" ON "JwtProfile"("fingerprint");

-- CreateIndex
CREATE INDEX "ApiAuthContext_workspaceId_idx" ON "ApiAuthContext"("workspaceId");

-- CreateIndex
CREATE INDEX "ApiAuthContext_apiServiceId_idx" ON "ApiAuthContext"("apiServiceId");

-- CreateIndex
CREATE INDEX "AuthorizationTestCase_workspaceId_idx" ON "AuthorizationTestCase"("workspaceId");

-- CreateIndex
CREATE INDEX "TestDataProfile_workspaceId_idx" ON "TestDataProfile"("workspaceId");

