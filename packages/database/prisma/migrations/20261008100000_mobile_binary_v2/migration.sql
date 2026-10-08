-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_STATIC_ANALYSIS_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_STATIC_ANALYSIS_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_ARTIFACT_UPLOADED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_DYNAMIC_ANALYSIS_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_DYNAMIC_ANALYSIS_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_TRAFFIC_CAPTURE_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_FINDING_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_FINDING_VERIFIED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_ARTIFACT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_ANALYSIS_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'BINARY_ANALYSIS_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'RUNTIME_INSTRUMENTATION_STARTED';

-- AlterTable
ALTER TABLE "MobileInstrumentationModule" ADD COLUMN     "platform" TEXT,
ADD COLUMN     "purpose" TEXT;

-- AlterTable
ALTER TABLE "MobileTestDevice" ADD COLUMN     "authorizationStatus" TEXT NOT NULL DEFAULT 'NOT_AUTHORIZED',
ADD COLUMN     "deviceType" TEXT NOT NULL DEFAULT 'ANDROID_EMULATOR',
ADD COLUMN     "environment" TEXT NOT NULL DEFAULT 'LAB',
ADD COLUMN     "ownership" TEXT NOT NULL DEFAULT 'DSRCLONE_MANAGED';

-- CreateTable
CREATE TABLE "MobileAnalysisPlan" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "profile" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "authorizationId" TEXT,
    "staticModules" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "dynamicModules" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "dynamicGate" TEXT NOT NULL DEFAULT 'NOT_REQUESTED',
    "dynamicGateReasons" JSONB NOT NULL DEFAULT '[]',
    "deviceId" TEXT,
    "trafficAnalysis" BOOLEAN NOT NULL DEFAULT false,
    "limits" JSONB NOT NULL DEFAULT '{}',
    "verificationPolicy" TEXT NOT NULL DEFAULT 'TARGETED_RETEST',
    "status" TEXT NOT NULL DEFAULT 'PLANNED',
    "scanId" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileAnalysisPlan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApplicationVersionLineage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "fromBuildId" TEXT NOT NULL,
    "toBuildId" TEXT NOT NULL,
    "summary" JSONB NOT NULL DEFAULT '{}',
    "comparedBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ApplicationVersionLineage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileFindingCarryForward" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "lineageId" TEXT NOT NULL,
    "crossBuildFingerprint" TEXT NOT NULL,
    "classification" TEXT NOT NULL,
    "fromFindingId" TEXT,
    "toFindingId" TEXT,
    "ruleId" TEXT,
    "title" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileFindingCarryForward_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileSecurityCoverage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "dimensions" JSONB NOT NULL DEFAULT '{}',
    "completion" TEXT NOT NULL DEFAULT 'COMPLETED_WITH_GAPS',
    "obfuscation" JSONB NOT NULL DEFAULT '{}',
    "packing" JSONB NOT NULL DEFAULT '{}',
    "computedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileSecurityCoverage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinarySecurityCoverage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "artifactId" TEXT NOT NULL,
    "dimensions" JSONB NOT NULL DEFAULT '{}',
    "completion" TEXT NOT NULL DEFAULT 'COMPLETED_WITH_GAPS',
    "computedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinarySecurityCoverage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "MobileAnalysisPlan_workspaceId_idx" ON "MobileAnalysisPlan"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileAnalysisPlan_buildId_idx" ON "MobileAnalysisPlan"("buildId");

-- CreateIndex
CREATE INDEX "MobileAnalysisPlan_applicationId_idx" ON "MobileAnalysisPlan"("applicationId");

-- CreateIndex
CREATE INDEX "ApplicationVersionLineage_workspaceId_idx" ON "ApplicationVersionLineage"("workspaceId");

-- CreateIndex
CREATE INDEX "ApplicationVersionLineage_applicationId_idx" ON "ApplicationVersionLineage"("applicationId");

-- CreateIndex
CREATE UNIQUE INDEX "ApplicationVersionLineage_fromBuildId_toBuildId_key" ON "ApplicationVersionLineage"("fromBuildId", "toBuildId");

-- CreateIndex
CREATE INDEX "MobileFindingCarryForward_workspaceId_idx" ON "MobileFindingCarryForward"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileFindingCarryForward_lineageId_idx" ON "MobileFindingCarryForward"("lineageId");

-- CreateIndex
CREATE INDEX "MobileFindingCarryForward_crossBuildFingerprint_idx" ON "MobileFindingCarryForward"("crossBuildFingerprint");

-- CreateIndex
CREATE INDEX "MobileSecurityCoverage_workspaceId_idx" ON "MobileSecurityCoverage"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileSecurityCoverage_buildId_idx" ON "MobileSecurityCoverage"("buildId");

-- CreateIndex
CREATE INDEX "BinarySecurityCoverage_workspaceId_idx" ON "BinarySecurityCoverage"("workspaceId");

-- CreateIndex
CREATE INDEX "BinarySecurityCoverage_artifactId_idx" ON "BinarySecurityCoverage"("artifactId");

-- AddForeignKey
ALTER TABLE "MobileAnalysisPlan" ADD CONSTRAINT "MobileAnalysisPlan_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "MobileApplication"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileAnalysisPlan" ADD CONSTRAINT "MobileAnalysisPlan_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApplicationVersionLineage" ADD CONSTRAINT "ApplicationVersionLineage_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "MobileApplication"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApplicationVersionLineage" ADD CONSTRAINT "ApplicationVersionLineage_fromBuildId_fkey" FOREIGN KEY ("fromBuildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApplicationVersionLineage" ADD CONSTRAINT "ApplicationVersionLineage_toBuildId_fkey" FOREIGN KEY ("toBuildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileFindingCarryForward" ADD CONSTRAINT "MobileFindingCarryForward_lineageId_fkey" FOREIGN KEY ("lineageId") REFERENCES "ApplicationVersionLineage"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileSecurityCoverage" ADD CONSTRAINT "MobileSecurityCoverage_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinarySecurityCoverage" ADD CONSTRAINT "BinarySecurityCoverage_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "BinaryArtifact"("id") ON DELETE CASCADE ON UPDATE CASCADE;

