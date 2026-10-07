-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssessmentProfile" ADD VALUE 'WIRELESS_PASSIVE_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'WIRELESS_PASSIVE_COMPREHENSIVE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'PCAP_ANALYSIS_ONLY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'WIRELESS_COMPLIANCE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'WIRELESS_LAB_VALIDATION';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'WIRELESS_CAPTURE_INTAKE';
ALTER TYPE "ScanStageType" ADD VALUE 'WIRELESS_PASSIVE_DISCOVERY';
ALTER TYPE "ScanStageType" ADD VALUE 'WIRELESS_PCAP_ANALYSIS';
ALTER TYPE "ScanStageType" ADD VALUE 'WIRELESS_POSTURE_ANALYSIS';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_ENVIRONMENT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_SENSOR_REGISTERED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_CAPTURE_UPLOADED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_CAPTURE_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_AP_DISCOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_SECURITY_DRIFT_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_SECURITY_EVENT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_POLICY_VIOLATION_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_ACTIVE_TOOL_BLOCKED';
ALTER TYPE "AuditAction" ADD VALUE 'WIRELESS_LAB_VALIDATION_REQUESTED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "wirelessAccessPointId" TEXT,
ADD COLUMN     "wirelessBssid" TEXT,
ADD COLUMN     "wirelessEnvironmentId" TEXT,
ADD COLUMN     "wirelessFindingType" TEXT,
ADD COLUMN     "wirelessFingerprint" TEXT;

-- CreateTable
CREATE TABLE "WirelessEnvironment" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "locationLabel" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'CORPORATE',
    "criticality" TEXT NOT NULL DEFAULT 'MEDIUM',
    "authorizationId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WirelessEnvironment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessScope" (
    "id" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "bssidAllowlist" JSONB NOT NULL,
    "ssidAllowlist" JSONB NOT NULL,
    "channelAllowlist" JSONB NOT NULL,
    "frequencyBands" JSONB NOT NULL,
    "maxCaptureDurationSeconds" INTEGER NOT NULL DEFAULT 3600,
    "approvedInterfaces" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WirelessScope_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessSensor" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT,
    "name" TEXT NOT NULL,
    "host" TEXT,
    "adapter" TEXT,
    "driver" TEXT,
    "interfaceName" TEXT,
    "supportedBands" JSONB NOT NULL,
    "monitorModeCapable" BOOLEAN NOT NULL DEFAULT false,
    "health" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "status" TEXT NOT NULL DEFAULT 'REGISTERED',
    "lastSeen" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WirelessSensor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessAccessPoint" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "bssid" TEXT NOT NULL,
    "ssid" TEXT NOT NULL DEFAULT '',
    "ssidHidden" BOOLEAN NOT NULL DEFAULT false,
    "vendor" TEXT,
    "channel" INTEGER,
    "frequencyMhz" INTEGER,
    "band" TEXT,
    "securityMode" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "encryption" TEXT,
    "authentication" TEXT,
    "pmf" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "wpsAdvertised" BOOLEAN NOT NULL DEFAULT false,
    "signalDbm" INTEGER,
    "approvedStatus" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "networkAssetId" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL,
    "lastSeen" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WirelessAccessPoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessStation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "addressFingerprint" TEXT NOT NULL,
    "rawAddress" TEXT,
    "accessPointId" TEXT,
    "associatedBssid" TEXT,
    "signalDbm" INTEGER,
    "source" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL,
    "lastSeen" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WirelessStation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessObservation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "accessPointId" TEXT NOT NULL,
    "sensorId" TEXT,
    "captureId" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "channel" INTEGER,
    "bssid" TEXT NOT NULL,
    "ssid" TEXT NOT NULL DEFAULT '',
    "securityMode" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "signalDbm" INTEGER,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WirelessObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessChannelObservation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "scanId" TEXT,
    "channel" INTEGER NOT NULL,
    "band" TEXT,
    "accessPointCount" INTEGER NOT NULL DEFAULT 0,
    "utilizationPercent" DOUBLE PRECISION,
    "noiseDbm" INTEGER,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WirelessChannelObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessCapture" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "sensorId" TEXT,
    "name" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "format" TEXT NOT NULL,
    "sizeBytes" BIGINT NOT NULL DEFAULT 0,
    "startTime" TIMESTAMP(3),
    "endTime" TIMESTAMP(3),
    "channels" JSONB NOT NULL,
    "artifactReference" TEXT,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "sanitizationStatus" TEXT NOT NULL DEFAULT 'PENDING',
    "analysisArtifacts" JSONB,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WirelessCapture_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApprovedWirelessProfile" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "ssid" TEXT NOT NULL,
    "bssid" TEXT,
    "securityMode" TEXT NOT NULL,
    "authentication" TEXT,
    "allowedChannels" JSONB NOT NULL,
    "allowedBands" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ApprovedWirelessProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessSecurityEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "accessPointId" TEXT,
    "type" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "bssid" TEXT,
    "confidence" TEXT NOT NULL DEFAULT 'LOW',
    "evidenceSummary" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WirelessSecurityEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessDriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "accessPointId" TEXT,
    "kind" TEXT NOT NULL,
    "bssid" TEXT NOT NULL,
    "ssid" TEXT NOT NULL DEFAULT '',
    "field" TEXT NOT NULL,
    "fromValue" TEXT,
    "toValue" TEXT,
    "securityDowngrade" BOOLEAN NOT NULL DEFAULT false,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WirelessDriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessAccessPointHistory" (
    "id" TEXT NOT NULL,
    "accessPointId" TEXT NOT NULL,
    "ssid" TEXT NOT NULL DEFAULT '',
    "channel" INTEGER,
    "securityMode" TEXT NOT NULL,
    "authentication" TEXT,
    "approvedStatus" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WirelessAccessPointHistory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WirelessScanSession" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "sensorId" TEXT,
    "scanId" TEXT,
    "profile" TEXT NOT NULL,
    "scopeSnapshot" JSONB NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "channels" JSONB NOT NULL,
    "observationCount" INTEGER NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL DEFAULT 'RUNNING',
    "budget" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WirelessScanSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "WirelessEnvironment_workspaceId_idx" ON "WirelessEnvironment"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "WirelessScope_environmentId_key" ON "WirelessScope"("environmentId");

-- CreateIndex
CREATE INDEX "WirelessSensor_workspaceId_idx" ON "WirelessSensor"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessSensor_environmentId_idx" ON "WirelessSensor"("environmentId");

-- CreateIndex
CREATE INDEX "WirelessAccessPoint_workspaceId_idx" ON "WirelessAccessPoint"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessAccessPoint_environmentId_idx" ON "WirelessAccessPoint"("environmentId");

-- CreateIndex
CREATE INDEX "WirelessAccessPoint_bssid_idx" ON "WirelessAccessPoint"("bssid");

-- CreateIndex
CREATE UNIQUE INDEX "WirelessAccessPoint_environmentId_bssid_key" ON "WirelessAccessPoint"("environmentId", "bssid");

-- CreateIndex
CREATE INDEX "WirelessStation_workspaceId_idx" ON "WirelessStation"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessStation_environmentId_idx" ON "WirelessStation"("environmentId");

-- CreateIndex
CREATE UNIQUE INDEX "WirelessStation_environmentId_addressFingerprint_key" ON "WirelessStation"("environmentId", "addressFingerprint");

-- CreateIndex
CREATE INDEX "WirelessObservation_workspaceId_idx" ON "WirelessObservation"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessObservation_environmentId_idx" ON "WirelessObservation"("environmentId");

-- CreateIndex
CREATE INDEX "WirelessObservation_accessPointId_idx" ON "WirelessObservation"("accessPointId");

-- CreateIndex
CREATE INDEX "WirelessChannelObservation_workspaceId_idx" ON "WirelessChannelObservation"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessChannelObservation_environmentId_channel_idx" ON "WirelessChannelObservation"("environmentId", "channel");

-- CreateIndex
CREATE INDEX "WirelessCapture_workspaceId_idx" ON "WirelessCapture"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessCapture_environmentId_idx" ON "WirelessCapture"("environmentId");

-- CreateIndex
CREATE UNIQUE INDEX "WirelessCapture_workspaceId_sha256_key" ON "WirelessCapture"("workspaceId", "sha256");

-- CreateIndex
CREATE INDEX "ApprovedWirelessProfile_workspaceId_idx" ON "ApprovedWirelessProfile"("workspaceId");

-- CreateIndex
CREATE INDEX "ApprovedWirelessProfile_environmentId_idx" ON "ApprovedWirelessProfile"("environmentId");

-- CreateIndex
CREATE INDEX "WirelessSecurityEvent_workspaceId_idx" ON "WirelessSecurityEvent"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessSecurityEvent_environmentId_idx" ON "WirelessSecurityEvent"("environmentId");

-- CreateIndex
CREATE INDEX "WirelessSecurityEvent_type_idx" ON "WirelessSecurityEvent"("type");

-- CreateIndex
CREATE INDEX "WirelessDriftEvent_workspaceId_idx" ON "WirelessDriftEvent"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessDriftEvent_environmentId_idx" ON "WirelessDriftEvent"("environmentId");

-- CreateIndex
CREATE INDEX "WirelessAccessPointHistory_accessPointId_idx" ON "WirelessAccessPointHistory"("accessPointId");

-- CreateIndex
CREATE INDEX "WirelessScanSession_workspaceId_idx" ON "WirelessScanSession"("workspaceId");

-- CreateIndex
CREATE INDEX "WirelessScanSession_environmentId_idx" ON "WirelessScanSession"("environmentId");

-- CreateIndex
CREATE INDEX "WirelessScanSession_scanId_idx" ON "WirelessScanSession"("scanId");

-- CreateIndex
CREATE INDEX "Finding_wirelessEnvironmentId_idx" ON "Finding"("wirelessEnvironmentId");

-- CreateIndex
CREATE INDEX "Finding_wirelessAccessPointId_idx" ON "Finding"("wirelessAccessPointId");

-- CreateIndex
CREATE INDEX "Finding_wirelessFingerprint_idx" ON "Finding"("wirelessFingerprint");

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_wirelessEnvironmentId_fkey" FOREIGN KEY ("wirelessEnvironmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_wirelessAccessPointId_fkey" FOREIGN KEY ("wirelessAccessPointId") REFERENCES "WirelessAccessPoint"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessEnvironment" ADD CONSTRAINT "WirelessEnvironment_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessScope" ADD CONSTRAINT "WirelessScope_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessSensor" ADD CONSTRAINT "WirelessSensor_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessSensor" ADD CONSTRAINT "WirelessSensor_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessAccessPoint" ADD CONSTRAINT "WirelessAccessPoint_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessAccessPoint" ADD CONSTRAINT "WirelessAccessPoint_networkAssetId_fkey" FOREIGN KEY ("networkAssetId") REFERENCES "Asset"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessStation" ADD CONSTRAINT "WirelessStation_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessStation" ADD CONSTRAINT "WirelessStation_accessPointId_fkey" FOREIGN KEY ("accessPointId") REFERENCES "WirelessAccessPoint"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessObservation" ADD CONSTRAINT "WirelessObservation_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessObservation" ADD CONSTRAINT "WirelessObservation_accessPointId_fkey" FOREIGN KEY ("accessPointId") REFERENCES "WirelessAccessPoint"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessObservation" ADD CONSTRAINT "WirelessObservation_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "WirelessSensor"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessObservation" ADD CONSTRAINT "WirelessObservation_captureId_fkey" FOREIGN KEY ("captureId") REFERENCES "WirelessCapture"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessChannelObservation" ADD CONSTRAINT "WirelessChannelObservation_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessChannelObservation" ADD CONSTRAINT "WirelessChannelObservation_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessCapture" ADD CONSTRAINT "WirelessCapture_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessCapture" ADD CONSTRAINT "WirelessCapture_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessCapture" ADD CONSTRAINT "WirelessCapture_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "WirelessSensor"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApprovedWirelessProfile" ADD CONSTRAINT "ApprovedWirelessProfile_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessSecurityEvent" ADD CONSTRAINT "WirelessSecurityEvent_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessSecurityEvent" ADD CONSTRAINT "WirelessSecurityEvent_accessPointId_fkey" FOREIGN KEY ("accessPointId") REFERENCES "WirelessAccessPoint"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessDriftEvent" ADD CONSTRAINT "WirelessDriftEvent_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessDriftEvent" ADD CONSTRAINT "WirelessDriftEvent_accessPointId_fkey" FOREIGN KEY ("accessPointId") REFERENCES "WirelessAccessPoint"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessAccessPointHistory" ADD CONSTRAINT "WirelessAccessPointHistory_accessPointId_fkey" FOREIGN KEY ("accessPointId") REFERENCES "WirelessAccessPoint"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessScanSession" ADD CONSTRAINT "WirelessScanSession_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "WirelessEnvironment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WirelessScanSession" ADD CONSTRAINT "WirelessScanSession_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "WirelessSensor"("id") ON DELETE SET NULL ON UPDATE CASCADE;

