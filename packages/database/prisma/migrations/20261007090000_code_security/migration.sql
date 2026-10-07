-- CreateEnum
CREATE TYPE "SourceKind" AS ENUM ('GIT_REPOSITORY', 'UPLOADED_ARCHIVE', 'LOCAL_SOURCE_SNAPSHOT');

-- CreateEnum
CREATE TYPE "SecretType" AS ENUM ('API_KEY', 'TOKEN', 'PRIVATE_KEY', 'PASSWORD', 'DATABASE_CREDENTIAL', 'CLOUD_CREDENTIAL', 'CERTIFICATE_SECRET', 'GENERIC_SECRET');

-- CreateEnum
CREATE TYPE "SecretLifecycleStatus" AS ENUM ('OPEN', 'ROTATION_REQUIRED', 'ROTATED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'RESOLVED');

-- CreateEnum
CREATE TYPE "SecretVerificationStatus" AS ENUM ('NOT_VERIFIED', 'VERIFIED_ACTIVE', 'VERIFIED_INACTIVE', 'VERIFICATION_FAILED');

-- CreateEnum
CREATE TYPE "SbomFormat" AS ENUM ('CYCLONEDX_JSON', 'SPDX_JSON', 'SPDX_TAG_VALUE');

-- CreateEnum
CREATE TYPE "QualityGateStatus" AS ENUM ('PASSED', 'FAILED', 'WARNING', 'NOT_EVALUATED');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssessmentProfile" ADD VALUE 'SOURCE_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'SOURCE_COMPREHENSIVE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'SECRETS_ONLY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'DEPENDENCIES_ONLY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'SAST_ONLY';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'SOURCE_ACQUISITION';
ALTER TYPE "ScanStageType" ADD VALUE 'LANGUAGE_DETECTION';
ALTER TYPE "ScanStageType" ADD VALUE 'SECRET_SCANNING';
ALTER TYPE "ScanStageType" ADD VALUE 'SAST';
ALTER TYPE "ScanStageType" ADD VALUE 'DEPENDENCY_INVENTORY';
ALTER TYPE "ScanStageType" ADD VALUE 'SCA';
ALTER TYPE "ScanStageType" ADD VALUE 'SBOM_GENERATION';
ALTER TYPE "ScanStageType" ADD VALUE 'QUALITY_GATE';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'SOURCE_REPOSITORY_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SOURCE_SCAN_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'SOURCE_SNAPSHOT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SAST_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'SECRET_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'DEPENDENCY_VULNERABILITY_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'SBOM_GENERATED';
ALTER TYPE "AuditAction" ADD VALUE 'QUALITY_GATE_EVALUATED';
ALTER TYPE "AuditAction" ADD VALUE 'SOURCE_FINDING_RESOLVED';
ALTER TYPE "AuditAction" ADD VALUE 'SOURCE_ARTIFACT_ACCESSED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "baselineStatus" TEXT,
ADD COLUMN     "codeFlow" JSONB,
ADD COLUMN     "componentPurl" TEXT,
ADD COLUMN     "dependencyScope" TEXT,
ADD COLUMN     "endColumn" INTEGER,
ADD COLUMN     "endLine" INTEGER,
ADD COLUMN     "filePath" TEXT,
ADD COLUMN     "fixedVersion" TEXT,
ADD COLUMN     "reachability" TEXT,
ADD COLUMN     "repositoryId" TEXT,
ADD COLUMN     "ruleId" TEXT,
ADD COLUMN     "snapshotId" TEXT,
ADD COLUMN     "startColumn" INTEGER,
ADD COLUMN     "startLine" INTEGER;

-- CreateTable
CREATE TABLE "SourceRepository" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "name" TEXT NOT NULL,
    "provider" TEXT,
    "remoteUrl" TEXT,
    "defaultBranch" TEXT,
    "visibility" TEXT NOT NULL DEFAULT 'PRIVATE',
    "sourceKind" "SourceKind" NOT NULL,
    "credentialReference" TEXT,
    "snapshotManifest" JSONB,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SourceRepository_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SourceSnapshot" (
    "id" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL,
    "scanId" TEXT,
    "commitSha" TEXT,
    "branch" TEXT,
    "snapshotHash" TEXT NOT NULL,
    "artifactReference" TEXT,
    "sourceKind" "SourceKind" NOT NULL,
    "fileCount" INTEGER NOT NULL DEFAULT 0,
    "totalSizeBytes" BIGINT NOT NULL DEFAULT 0,
    "files" JSONB NOT NULL DEFAULT '[]',
    "manifests" JSONB NOT NULL DEFAULT '{}',
    "languages" JSONB NOT NULL DEFAULT '[]',
    "frameworks" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "buildSystems" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SourceSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SoftwareComponent" (
    "id" TEXT NOT NULL,
    "snapshotId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT,
    "ecosystem" TEXT NOT NULL,
    "purl" TEXT NOT NULL,
    "sourceManifest" TEXT NOT NULL,
    "scope" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "dependencyScope" TEXT NOT NULL DEFAULT 'RUNTIME',
    "licenses" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "supplier" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SoftwareComponent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SoftwareBillOfMaterials" (
    "id" TEXT NOT NULL,
    "snapshotId" TEXT NOT NULL,
    "scanId" TEXT,
    "format" "SbomFormat" NOT NULL,
    "specVersion" TEXT NOT NULL,
    "checksum" TEXT NOT NULL,
    "artifactRef" TEXT,
    "componentCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SoftwareBillOfMaterials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecretFindingMetadata" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "secretType" "SecretType" NOT NULL,
    "detector" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "redactedPreview" TEXT,
    "filePath" TEXT,
    "startLine" INTEGER,
    "endLine" INTEGER,
    "commitSha" TEXT,
    "verificationStatus" "SecretVerificationStatus" NOT NULL DEFAULT 'NOT_VERIFIED',
    "lifecycleStatus" "SecretLifecycleStatus" NOT NULL DEFAULT 'OPEN',
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecretFindingMetadata_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SourceScanExclusion" (
    "id" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL,
    "exclusionType" TEXT NOT NULL,
    "pattern" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SourceScanExclusion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "QualityGateResult" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "snapshotId" TEXT,
    "status" "QualityGateStatus" NOT NULL,
    "policyVersion" TEXT NOT NULL,
    "failedRules" JSONB NOT NULL DEFAULT '[]',
    "warningRules" JSONB NOT NULL DEFAULT '[]',
    "summary" JSONB NOT NULL DEFAULT '{}',
    "evaluatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "QualityGateResult_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SourceRepository_workspaceId_idx" ON "SourceRepository"("workspaceId");

-- CreateIndex
CREATE INDEX "SourceRepository_targetId_idx" ON "SourceRepository"("targetId");

-- CreateIndex
CREATE INDEX "SourceSnapshot_repositoryId_idx" ON "SourceSnapshot"("repositoryId");

-- CreateIndex
CREATE INDEX "SourceSnapshot_scanId_idx" ON "SourceSnapshot"("scanId");

-- CreateIndex
CREATE INDEX "SourceSnapshot_snapshotHash_idx" ON "SourceSnapshot"("snapshotHash");

-- CreateIndex
CREATE INDEX "SoftwareComponent_snapshotId_idx" ON "SoftwareComponent"("snapshotId");

-- CreateIndex
CREATE INDEX "SoftwareComponent_ecosystem_name_idx" ON "SoftwareComponent"("ecosystem", "name");

-- CreateIndex
CREATE UNIQUE INDEX "SoftwareComponent_snapshotId_purl_key" ON "SoftwareComponent"("snapshotId", "purl");

-- CreateIndex
CREATE INDEX "SoftwareBillOfMaterials_snapshotId_idx" ON "SoftwareBillOfMaterials"("snapshotId");

-- CreateIndex
CREATE INDEX "SoftwareBillOfMaterials_scanId_idx" ON "SoftwareBillOfMaterials"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "SecretFindingMetadata_findingId_key" ON "SecretFindingMetadata"("findingId");

-- CreateIndex
CREATE INDEX "SecretFindingMetadata_fingerprint_idx" ON "SecretFindingMetadata"("fingerprint");

-- CreateIndex
CREATE INDEX "SecretFindingMetadata_lifecycleStatus_idx" ON "SecretFindingMetadata"("lifecycleStatus");

-- CreateIndex
CREATE INDEX "SourceScanExclusion_repositoryId_idx" ON "SourceScanExclusion"("repositoryId");

-- CreateIndex
CREATE INDEX "QualityGateResult_scanId_idx" ON "QualityGateResult"("scanId");

-- AddForeignKey
ALTER TABLE "SourceRepository" ADD CONSTRAINT "SourceRepository_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SourceSnapshot" ADD CONSTRAINT "SourceSnapshot_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "SourceRepository"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoftwareComponent" ADD CONSTRAINT "SoftwareComponent_snapshotId_fkey" FOREIGN KEY ("snapshotId") REFERENCES "SourceSnapshot"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoftwareBillOfMaterials" ADD CONSTRAINT "SoftwareBillOfMaterials_snapshotId_fkey" FOREIGN KEY ("snapshotId") REFERENCES "SourceSnapshot"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecretFindingMetadata" ADD CONSTRAINT "SecretFindingMetadata_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SourceScanExclusion" ADD CONSTRAINT "SourceScanExclusion_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "SourceRepository"("id") ON DELETE CASCADE ON UPDATE CASCADE;

