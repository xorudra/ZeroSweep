-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssessmentProfile" ADD VALUE 'BINARY_METADATA_ONLY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'BINARY_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'BINARY_ASSESSMENT';
ALTER TYPE "AssessmentProfile" ADD VALUE 'BINARY_COMPREHENSIVE_STATIC';
ALTER TYPE "AssessmentProfile" ADD VALUE 'BINARY_DEPENDENCY_ANALYSIS';
ALTER TYPE "AssessmentProfile" ADD VALUE 'BINARY_CONTROLLED_DEBUG';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'BINARY_ARTIFACT_INTAKE';
ALTER TYPE "ScanStageType" ADD VALUE 'BINARY_METADATA_EXTRACTION';
ALTER TYPE "ScanStageType" ADD VALUE 'BINARY_HARDENING_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'BINARY_STATIC_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'BINARY_DEBUG_SESSION';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'BINARY_UPLOADED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_STATIC_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_STATIC_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_ARTIFACT_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_DECOMPILATION_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_DIFF_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_DEBUG_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_DEBUG_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_DEBUG_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_DEBUG_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_DEBUG_CANCELLED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_CRASH_CAPTURED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_DEBUG_ACTION_BLOCKED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "binaryArtifactHash" TEXT,
ADD COLUMN     "binaryArtifactId" TEXT,
ADD COLUMN     "binaryComponent" TEXT,
ADD COLUMN     "binaryFindingType" TEXT,
ADD COLUMN     "binaryFingerprint" TEXT,
ADD COLUMN     "binaryReachability" TEXT,
ADD COLUMN     "staticConfidence" TEXT;

-- AlterTable
ALTER TABLE "SoftwareComponent" ADD COLUMN     "binaryArtifactId" TEXT;

-- AlterTable
ALTER TABLE "SoftwareBillOfMaterials" ADD COLUMN     "binaryArtifactId" TEXT;

-- AlterTable
ALTER TABLE "MobileNativeLibrary" ADD COLUMN     "binaryArtifactId" TEXT;

-- CreateTable
CREATE TABLE "BinaryArtifact" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "name" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'UPLOAD',
    "sourceRef" TEXT,
    "mobileBuildId" TEXT,
    "containerImageId" TEXT,
    "sha256" TEXT NOT NULL,
    "sha1" TEXT,
    "sizeBytes" BIGINT NOT NULL DEFAULT 0,
    "format" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "kind" TEXT,
    "architecture" TEXT,
    "bitness" INTEGER,
    "endianness" TEXT,
    "platform" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'PRODUCTION',
    "artifactReference" TEXT,
    "analysisArtifacts" JSONB,
    "status" TEXT NOT NULL DEFAULT 'REGISTERED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BinaryArtifact_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinarySection" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT,
    "offset" BIGINT,
    "size" BIGINT,
    "virtualAddress" TEXT,
    "permissions" TEXT,
    "entropy" DOUBLE PRECISION,
    "source" TEXT NOT NULL DEFAULT 'binary-platform-analysis',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinarySection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryHardeningProfile" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "profile" JSONB NOT NULL DEFAULT '[]',
    "assessedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryHardeningProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryFunction" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "address" TEXT,
    "size" INTEGER,
    "callingConvention" TEXT,
    "fingerprint" TEXT,
    "referencesRiskyApi" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.7,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryFunction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryImport" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "library" TEXT NOT NULL,
    "symbol" TEXT NOT NULL,
    "address" TEXT,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryImport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryExport" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "symbol" TEXT NOT NULL,
    "address" TEXT,
    "type" TEXT,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryExport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinarySymbol" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT,
    "binding" TEXT,
    "address" TEXT,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinarySymbol_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryString" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "encoding" TEXT NOT NULL DEFAULT 'ASCII',
    "category" TEXT NOT NULL DEFAULT 'GENERIC',
    "location" TEXT,
    "secretFingerprint" TEXT,
    "secretType" TEXT,
    "redactedPreview" TEXT,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryString_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryDependency" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "library" TEXT NOT NULL,
    "version" TEXT,
    "path" TEXT,
    "platform" TEXT,
    "purl" TEXT,
    "cpe" TEXT,
    "sourceKind" TEXT NOT NULL DEFAULT 'DETECTED_LINKED',
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.8,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryDependency_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryCryptoReference" (
    "id" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryCryptoReference_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryDiff" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "baseArtifactId" TEXT NOT NULL,
    "targetArtifactId" TEXT NOT NULL,
    "summary" JSONB NOT NULL DEFAULT '{}',
    "regressions" JSONB NOT NULL DEFAULT '[]',
    "detail" JSONB NOT NULL DEFAULT '{}',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryDiff_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryDebugSession" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "environment" TEXT NOT NULL DEFAULT 'LAB',
    "status" TEXT NOT NULL DEFAULT 'REQUESTED',
    "operations" JSONB NOT NULL DEFAULT '[]',
    "policyDecision" JSONB NOT NULL DEFAULT '{}',
    "networkPolicy" TEXT NOT NULL DEFAULT 'NO_NETWORK',
    "timeoutSeconds" INTEGER NOT NULL DEFAULT 1800,
    "killSwitchChecked" BOOLEAN NOT NULL DEFAULT false,
    "requestedBy" TEXT NOT NULL,
    "approvedBy" TEXT,
    "startedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryDebugSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinaryCrash" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "sessionId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "signal" TEXT NOT NULL,
    "exceptionType" TEXT,
    "faultingFunction" TEXT,
    "stackSummary" JSONB NOT NULL DEFAULT '[]',
    "registerSummary" JSONB NOT NULL DEFAULT '{}',
    "inputReference" TEXT,
    "triage" TEXT NOT NULL DEFAULT 'NEEDS_REVIEW',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinaryCrash_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "BinaryArtifact_workspaceId_idx" ON "BinaryArtifact"("workspaceId");

-- CreateIndex
CREATE INDEX "BinaryArtifact_targetId_idx" ON "BinaryArtifact"("targetId");

-- CreateIndex
CREATE INDEX "BinaryArtifact_sha256_idx" ON "BinaryArtifact"("sha256");

-- CreateIndex
CREATE UNIQUE INDEX "BinaryArtifact_workspaceId_sha256_key" ON "BinaryArtifact"("workspaceId", "sha256");

-- CreateIndex
CREATE INDEX "BinarySection_artifactId_idx" ON "BinarySection"("artifactId");

-- CreateIndex
CREATE UNIQUE INDEX "BinarySection_artifactId_name_key" ON "BinarySection"("artifactId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "BinaryHardeningProfile_artifactId_key" ON "BinaryHardeningProfile"("artifactId");

-- CreateIndex
CREATE INDEX "BinaryHardeningProfile_workspaceId_idx" ON "BinaryHardeningProfile"("workspaceId");

-- CreateIndex
CREATE INDEX "BinaryFunction_artifactId_idx" ON "BinaryFunction"("artifactId");

-- CreateIndex
CREATE INDEX "BinaryFunction_workspaceId_name_idx" ON "BinaryFunction"("workspaceId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "BinaryFunction_artifactId_name_address_key" ON "BinaryFunction"("artifactId", "name", "address");

-- CreateIndex
CREATE INDEX "BinaryImport_artifactId_idx" ON "BinaryImport"("artifactId");

-- CreateIndex
CREATE INDEX "BinaryImport_workspaceId_symbol_idx" ON "BinaryImport"("workspaceId", "symbol");

-- CreateIndex
CREATE INDEX "BinaryExport_artifactId_idx" ON "BinaryExport"("artifactId");

-- CreateIndex
CREATE INDEX "BinarySymbol_artifactId_idx" ON "BinarySymbol"("artifactId");

-- CreateIndex
CREATE INDEX "BinaryString_artifactId_idx" ON "BinaryString"("artifactId");

-- CreateIndex
CREATE INDEX "BinaryString_artifactId_category_idx" ON "BinaryString"("artifactId", "category");

-- CreateIndex
CREATE INDEX "BinaryDependency_artifactId_idx" ON "BinaryDependency"("artifactId");

-- CreateIndex
CREATE INDEX "BinaryDependency_workspaceId_library_idx" ON "BinaryDependency"("workspaceId", "library");

-- CreateIndex
CREATE UNIQUE INDEX "BinaryDependency_artifactId_library_key" ON "BinaryDependency"("artifactId", "library");

-- CreateIndex
CREATE INDEX "BinaryCryptoReference_artifactId_idx" ON "BinaryCryptoReference"("artifactId");

-- CreateIndex
CREATE INDEX "BinaryDiff_workspaceId_idx" ON "BinaryDiff"("workspaceId");

-- CreateIndex
CREATE INDEX "BinaryDiff_baseArtifactId_idx" ON "BinaryDiff"("baseArtifactId");

-- CreateIndex
CREATE INDEX "BinaryDiff_targetArtifactId_idx" ON "BinaryDiff"("targetArtifactId");

-- CreateIndex
CREATE INDEX "BinaryDebugSession_workspaceId_idx" ON "BinaryDebugSession"("workspaceId");

-- CreateIndex
CREATE INDEX "BinaryDebugSession_artifactId_idx" ON "BinaryDebugSession"("artifactId");

-- CreateIndex
CREATE INDEX "BinaryCrash_workspaceId_fingerprint_idx" ON "BinaryCrash"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "BinaryCrash_artifactId_idx" ON "BinaryCrash"("artifactId");

-- CreateIndex
CREATE INDEX "Finding_binaryArtifactId_idx" ON "Finding"("binaryArtifactId");

-- CreateIndex
CREATE INDEX "Finding_binaryFingerprint_idx" ON "Finding"("binaryFingerprint");

-- CreateIndex
CREATE INDEX "SoftwareComponent_binaryArtifactId_idx" ON "SoftwareComponent"("binaryArtifactId");

-- CreateIndex
CREATE UNIQUE INDEX "SoftwareComponent_binaryArtifactId_purl_key" ON "SoftwareComponent"("binaryArtifactId", "purl");

-- CreateIndex
CREATE INDEX "SoftwareBillOfMaterials_binaryArtifactId_idx" ON "SoftwareBillOfMaterials"("binaryArtifactId");

-- CreateIndex
CREATE INDEX "MobileNativeLibrary_binaryArtifactId_idx" ON "MobileNativeLibrary"("binaryArtifactId");

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_binaryArtifactId_fkey" FOREIGN KEY ("binaryArtifactId") REFERENCES "BinaryArtifact"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoftwareComponent" ADD CONSTRAINT "SoftwareComponent_binaryArtifactId_fkey" FOREIGN KEY ("binaryArtifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoftwareBillOfMaterials" ADD CONSTRAINT "SoftwareBillOfMaterials_binaryArtifactId_fkey" FOREIGN KEY ("binaryArtifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileNativeLibrary" ADD CONSTRAINT "MobileNativeLibrary_binaryArtifactId_fkey" FOREIGN KEY ("binaryArtifactId") REFERENCES "BinaryArtifact"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryArtifact" ADD CONSTRAINT "BinaryArtifact_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryArtifact" ADD CONSTRAINT "BinaryArtifact_mobileBuildId_fkey" FOREIGN KEY ("mobileBuildId") REFERENCES "MobileBuild"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryArtifact" ADD CONSTRAINT "BinaryArtifact_containerImageId_fkey" FOREIGN KEY ("containerImageId") REFERENCES "ContainerImage"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinarySection" ADD CONSTRAINT "BinarySection_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryHardeningProfile" ADD CONSTRAINT "BinaryHardeningProfile_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryFunction" ADD CONSTRAINT "BinaryFunction_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryImport" ADD CONSTRAINT "BinaryImport_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryExport" ADD CONSTRAINT "BinaryExport_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinarySymbol" ADD CONSTRAINT "BinarySymbol_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryString" ADD CONSTRAINT "BinaryString_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryDependency" ADD CONSTRAINT "BinaryDependency_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryCryptoReference" ADD CONSTRAINT "BinaryCryptoReference_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryDiff" ADD CONSTRAINT "BinaryDiff_baseArtifactId_fkey" FOREIGN KEY ("baseArtifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryDiff" ADD CONSTRAINT "BinaryDiff_targetArtifactId_fkey" FOREIGN KEY ("targetArtifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryDebugSession" ADD CONSTRAINT "BinaryDebugSession_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryCrash" ADD CONSTRAINT "BinaryCrash_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinaryCrash" ADD CONSTRAINT "BinaryCrash_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "BinaryDebugSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

