-- CreateEnum
CREATE TYPE "MobilePlatform" AS ENUM ('ANDROID', 'IOS');

-- AlterEnum
ALTER TYPE "TargetType" ADD VALUE 'MOBILE_APP';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssessmentProfile" ADD VALUE 'MOBILE_STATIC_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'MOBILE_STATIC_COMPREHENSIVE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'MOBILE_SECRETS_ONLY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'MOBILE_BINARY_ANALYSIS';
ALTER TYPE "AssessmentProfile" ADD VALUE 'MOBILE_DYNAMIC_CONTROLLED';
ALTER TYPE "AssessmentProfile" ADD VALUE 'MOBILE_FULL_CONTROLLED';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'MOBILE_ARTIFACT_INTAKE';
ALTER TYPE "ScanStageType" ADD VALUE 'MOBILE_METADATA_EXTRACTION';
ALTER TYPE "ScanStageType" ADD VALUE 'MOBILE_MANIFEST_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'MOBILE_STATIC_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'MOBILE_BINARY_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'MOBILE_DYNAMIC_SESSION';
ALTER TYPE "ScanStageType" ADD VALUE 'MOBILE_TRAFFIC_ANALYSIS';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_APP_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_BUILD_UPLOADED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_STATIC_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_STATIC_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_DYNAMIC_SESSION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_DYNAMIC_SESSION_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_DYNAMIC_SESSION_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_DYNAMIC_SESSION_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_ARTIFACT_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_TRAFFIC_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_INSTRUMENTATION_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_INSTRUMENTATION_STOPPED';
ALTER TYPE "AuditAction" ADD VALUE 'MOBILE_DYNAMIC_ACTION_BLOCKED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "crossBuildFingerprint" TEXT,
ADD COLUMN     "dynamicConfirmed" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "masvsControl" TEXT,
ADD COLUMN     "mobileApplicationId" TEXT,
ADD COLUMN     "mobileBuildHash" TEXT,
ADD COLUMN     "mobileBuildId" TEXT,
ADD COLUMN     "mobileComponent" TEXT,
ADD COLUMN     "mobileFindingType" TEXT,
ADD COLUMN     "mobilePlatform" TEXT,
ADD COLUMN     "owaspMobile" TEXT;

-- AlterTable
ALTER TABLE "SoftwareComponent" ADD COLUMN     "buildId" TEXT;

-- AlterTable
ALTER TABLE "SoftwareBillOfMaterials" ADD COLUMN     "buildId" TEXT;

-- AlterTable
ALTER TABLE "QualityGateResult" ADD COLUMN     "buildId" TEXT;

-- CreateTable
CREATE TABLE "MobileApplication" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "name" TEXT NOT NULL,
    "platform" "MobilePlatform" NOT NULL,
    "packageName" TEXT,
    "bundleId" TEXT,
    "owner" TEXT,
    "projectRef" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'MEDIUM',
    "status" TEXT NOT NULL DEFAULT 'REGISTERED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MobileApplication_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileBuild" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "versionName" TEXT,
    "versionCode" INTEGER,
    "buildNumber" TEXT,
    "artifactHash" TEXT NOT NULL,
    "artifactFormat" TEXT NOT NULL,
    "artifactReference" TEXT,
    "artifactSizeBytes" BIGINT NOT NULL DEFAULT 0,
    "signingMetadata" JSONB NOT NULL DEFAULT '{}',
    "minOsVersion" TEXT,
    "targetOsVersion" TEXT,
    "architectures" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "analysisArtifacts" JSONB NOT NULL DEFAULT '{}',
    "status" TEXT NOT NULL DEFAULT 'UPLOADED',
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastScanAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileBuild_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileDeepLink" (
    "id" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scheme" TEXT NOT NULL,
    "host" TEXT,
    "pathPrefix" TEXT,
    "autoVerify" BOOLEAN NOT NULL DEFAULT false,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileDeepLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileAppComponent" (
    "id" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "exported" BOOLEAN NOT NULL DEFAULT false,
    "permission" TEXT,
    "intentActions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileAppComponent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileEndpoint" (
    "id" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'HTTPS',
    "classification" TEXT NOT NULL DEFAULT 'DISCOVERED_REFERENCE',
    "linkedAssetId" TEXT,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileEndpoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileNativeLibrary" (
    "id" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "architecture" TEXT,
    "sha256" TEXT,
    "pie" BOOLEAN,
    "nx" BOOLEAN,
    "stackCanary" BOOLEAN,
    "relro" TEXT,
    "stripped" BOOLEAN,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileNativeLibrary_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileTestDevice" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "platform" "MobilePlatform" NOT NULL,
    "deviceKind" TEXT NOT NULL DEFAULT 'EMULATOR',
    "osVersion" TEXT,
    "capabilities" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "availability" TEXT NOT NULL DEFAULT 'AVAILABLE',
    "health" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "dedicatedNetwork" BOOLEAN NOT NULL DEFAULT true,
    "lastResetAt" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'REGISTERED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MobileTestDevice_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileTrafficSession" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "deviceId" TEXT,
    "proxyTool" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'REQUESTED',
    "startedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "hosts" JSONB NOT NULL DEFAULT '[]',
    "requestCount" INTEGER NOT NULL DEFAULT 0,
    "bytesCaptured" BIGINT NOT NULL DEFAULT 0,
    "artifactRef" TEXT,
    "sanitizationState" TEXT NOT NULL DEFAULT 'PENDING',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileTrafficSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileInstrumentationModule" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "tool" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "moduleHash" TEXT NOT NULL,
    "capability" TEXT NOT NULL DEFAULT 'DYNAMIC_INSTRUMENTATION',
    "riskClassification" TEXT NOT NULL DEFAULT 'REVIEW_REQUIRED',
    "approved" BOOLEAN NOT NULL DEFAULT false,
    "approvedBy" TEXT,
    "status" TEXT NOT NULL DEFAULT 'REGISTERED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MobileInstrumentationModule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MobileDynamicSession" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "deviceId" TEXT,
    "profile" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'REQUESTED',
    "requestedActions" JSONB NOT NULL DEFAULT '[]',
    "blockedReasons" JSONB NOT NULL DEFAULT '[]',
    "moduleIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "killSwitchChecked" BOOLEAN NOT NULL DEFAULT false,
    "cleanupState" TEXT NOT NULL DEFAULT 'PENDING',
    "createdBy" TEXT NOT NULL,
    "approvedBy" TEXT,
    "startedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MobileDynamicSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "MobileApplication_workspaceId_idx" ON "MobileApplication"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileApplication_targetId_idx" ON "MobileApplication"("targetId");

-- CreateIndex
CREATE UNIQUE INDEX "MobileApplication_workspaceId_platform_packageName_key" ON "MobileApplication"("workspaceId", "platform", "packageName");

-- CreateIndex
CREATE INDEX "MobileBuild_workspaceId_idx" ON "MobileBuild"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileBuild_applicationId_idx" ON "MobileBuild"("applicationId");

-- CreateIndex
CREATE INDEX "MobileBuild_artifactHash_idx" ON "MobileBuild"("artifactHash");

-- CreateIndex
CREATE UNIQUE INDEX "MobileBuild_applicationId_artifactHash_key" ON "MobileBuild"("applicationId", "artifactHash");

-- CreateIndex
CREATE INDEX "MobileDeepLink_buildId_idx" ON "MobileDeepLink"("buildId");

-- CreateIndex
CREATE INDEX "MobileDeepLink_workspaceId_idx" ON "MobileDeepLink"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileAppComponent_buildId_idx" ON "MobileAppComponent"("buildId");

-- CreateIndex
CREATE INDEX "MobileAppComponent_workspaceId_idx" ON "MobileAppComponent"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileEndpoint_buildId_idx" ON "MobileEndpoint"("buildId");

-- CreateIndex
CREATE INDEX "MobileEndpoint_workspaceId_idx" ON "MobileEndpoint"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileEndpoint_host_idx" ON "MobileEndpoint"("host");

-- CreateIndex
CREATE INDEX "MobileNativeLibrary_buildId_idx" ON "MobileNativeLibrary"("buildId");

-- CreateIndex
CREATE INDEX "MobileNativeLibrary_workspaceId_idx" ON "MobileNativeLibrary"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileTestDevice_workspaceId_idx" ON "MobileTestDevice"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileTrafficSession_workspaceId_idx" ON "MobileTrafficSession"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileTrafficSession_buildId_idx" ON "MobileTrafficSession"("buildId");

-- CreateIndex
CREATE INDEX "MobileInstrumentationModule_workspaceId_idx" ON "MobileInstrumentationModule"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "MobileInstrumentationModule_workspaceId_name_version_key" ON "MobileInstrumentationModule"("workspaceId", "name", "version");

-- CreateIndex
CREATE INDEX "MobileDynamicSession_workspaceId_idx" ON "MobileDynamicSession"("workspaceId");

-- CreateIndex
CREATE INDEX "MobileDynamicSession_buildId_idx" ON "MobileDynamicSession"("buildId");

-- CreateIndex
CREATE INDEX "Finding_mobileApplicationId_idx" ON "Finding"("mobileApplicationId");

-- CreateIndex
CREATE INDEX "Finding_mobileBuildId_idx" ON "Finding"("mobileBuildId");

-- CreateIndex
CREATE INDEX "Finding_crossBuildFingerprint_idx" ON "Finding"("crossBuildFingerprint");

-- CreateIndex
CREATE INDEX "SoftwareComponent_buildId_idx" ON "SoftwareComponent"("buildId");

-- CreateIndex
CREATE UNIQUE INDEX "SoftwareComponent_buildId_purl_key" ON "SoftwareComponent"("buildId", "purl");

-- CreateIndex
CREATE INDEX "SoftwareBillOfMaterials_buildId_idx" ON "SoftwareBillOfMaterials"("buildId");

-- CreateIndex
CREATE INDEX "QualityGateResult_buildId_idx" ON "QualityGateResult"("buildId");

-- AddForeignKey
ALTER TABLE "SoftwareComponent" ADD CONSTRAINT "SoftwareComponent_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoftwareBillOfMaterials" ADD CONSTRAINT "SoftwareBillOfMaterials_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileApplication" ADD CONSTRAINT "MobileApplication_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileBuild" ADD CONSTRAINT "MobileBuild_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "MobileApplication"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileDeepLink" ADD CONSTRAINT "MobileDeepLink_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileAppComponent" ADD CONSTRAINT "MobileAppComponent_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileEndpoint" ADD CONSTRAINT "MobileEndpoint_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileNativeLibrary" ADD CONSTRAINT "MobileNativeLibrary_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileTestDevice" ADD CONSTRAINT "MobileTestDevice_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileTrafficSession" ADD CONSTRAINT "MobileTrafficSession_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileTrafficSession" ADD CONSTRAINT "MobileTrafficSession_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "MobileTestDevice"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileDynamicSession" ADD CONSTRAINT "MobileDynamicSession_buildId_fkey" FOREIGN KEY ("buildId") REFERENCES "MobileBuild"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MobileDynamicSession" ADD CONSTRAINT "MobileDynamicSession_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "MobileTestDevice"("id") ON DELETE SET NULL ON UPDATE CASCADE;

