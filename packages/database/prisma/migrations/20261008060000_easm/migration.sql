-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'EASM_PROGRAM_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_ROOT_ASSET_ADDED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_ROOT_ASSET_VERIFIED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_ACTIVE_TESTING_AUTHORIZED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_DISCOVERY_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_DISCOVERY_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_CANDIDATE_DISCOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_ASSET_PROMOTED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_ASSET_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_OWNERSHIP_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_EXPOSURE_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_DRIFT_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'EASM_BASELINE_CREATED';

-- CreateTable
CREATE TABLE "EasmProgram" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "monitoringEnabled" BOOLEAN NOT NULL DEFAULT false,
    "monitoringTier" TEXT NOT NULL DEFAULT 'DAILY',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EasmProgram_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmRootAsset" (
    "id" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "unicodeValue" TEXT,
    "authorizationStatus" TEXT NOT NULL DEFAULT 'PENDING',
    "authorizationMethod" TEXT,
    "authorizedBy" TEXT,
    "authorizedAt" TIMESTAMP(3),
    "authorizationExpiresAt" TIMESTAMP(3),
    "activeTestingAllowed" BOOLEAN NOT NULL DEFAULT false,
    "activeTestingStatus" TEXT NOT NULL DEFAULT 'NOT_AUTHORIZED',
    "activeTestingBy" TEXT,
    "activeTestingAt" TIMESTAMP(3),
    "verificationChallenge" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EasmRootAsset_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmDiscoveryPolicy" (
    "id" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "mode" TEXT NOT NULL DEFAULT 'PASSIVE_ONLY',
    "passiveDiscovery" BOOLEAN NOT NULL DEFAULT true,
    "dnsResolution" BOOLEAN NOT NULL DEFAULT true,
    "certificateDiscovery" BOOLEAN NOT NULL DEFAULT true,
    "httpProbing" BOOLEAN NOT NULL DEFAULT false,
    "serviceDiscovery" BOOLEAN NOT NULL DEFAULT false,
    "technologyDetection" BOOLEAN NOT NULL DEFAULT true,
    "historicalUrls" BOOLEAN NOT NULL DEFAULT false,
    "frequency" TEXT NOT NULL DEFAULT 'DAILY',
    "maxCandidatesPerRun" INTEGER NOT NULL DEFAULT 1000,
    "allowPromotion" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EasmDiscoveryPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmServiceDiscoveryProfile" (
    "id" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "ports" INTEGER[] DEFAULT ARRAY[80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443]::INTEGER[],
    "ratePerSecond" INTEGER NOT NULL DEFAULT 100,
    "timeoutMs" INTEGER NOT NULL DEFAULT 1500,
    "retries" INTEGER NOT NULL DEFAULT 1,
    "probeLevel" TEXT NOT NULL DEFAULT 'CONNECT',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EasmServiceDiscoveryProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmAssetCandidate" (
    "id" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "rootAssetId" TEXT,
    "type" TEXT NOT NULL,
    "normalizedValue" TEXT NOT NULL,
    "unicodeValue" TEXT,
    "suspiciousIdn" BOOLEAN NOT NULL DEFAULT false,
    "status" TEXT NOT NULL DEFAULT 'NEW',
    "lifecycle" TEXT NOT NULL DEFAULT 'DISCOVERED',
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "ownershipStatus" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "ownershipConfidence" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "activeTestingStatus" TEXT NOT NULL DEFAULT 'NOT_AUTHORIZED',
    "exposureState" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'UNSPECIFIED',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "missCount" INTEGER NOT NULL DEFAULT 0,
    "promotedAssetId" TEXT,
    "promotedTargetId" TEXT,
    "mergedIntoId" TEXT,
    "technicalOwner" TEXT,
    "businessOwner" TEXT,
    "team" TEXT,
    "application" TEXT,
    "businessUnit" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EasmAssetCandidate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssetDiscoveryObservation" (
    "id" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "rootAssetId" TEXT,
    "source" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "rawReference" TEXT NOT NULL DEFAULT '',
    "relationship" TEXT,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AssetDiscoveryObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmOwnershipEvidence" (
    "id" TEXT NOT NULL,
    "candidateId" TEXT,
    "rootAssetId" TEXT,
    "workspaceId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "reference" TEXT NOT NULL,
    "detail" TEXT NOT NULL DEFAULT '',
    "createdBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmOwnershipEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DnsSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "candidateId" TEXT,
    "domain" TEXT NOT NULL,
    "records" JSONB NOT NULL DEFAULT '[]',
    "source" TEXT NOT NULL,
    "hash" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DnsSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DanglingDnsCandidate" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "cnameTarget" TEXT NOT NULL,
    "service" TEXT,
    "evidence" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DanglingDnsCandidate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmCertificate" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "subject" TEXT NOT NULL DEFAULT '',
    "issuer" TEXT NOT NULL DEFAULT '',
    "sans" JSONB NOT NULL DEFAULT '[]',
    "notBefore" TIMESTAMP(3),
    "notAfter" TIMESTAMP(3),
    "signatureAlgorithm" TEXT NOT NULL DEFAULT '',
    "keyType" TEXT NOT NULL DEFAULT '',
    "keyBits" INTEGER,
    "state" TEXT NOT NULL DEFAULT 'HEALTHY',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmCertificate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmCertificateObservation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "certificateId" TEXT NOT NULL,
    "candidateId" TEXT,
    "host" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmCertificateObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HostExposureSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "resolvedIps" JSONB NOT NULL DEFAULT '[]',
    "internetVisibility" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "httpState" JSONB NOT NULL DEFAULT '{}',
    "services" JSONB NOT NULL DEFAULT '[]',
    "technologies" JSONB NOT NULL DEFAULT '[]',
    "certificateFingerprint" TEXT,
    "riskSignals" JSONB NOT NULL DEFAULT '[]',
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "HostExposureSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ServiceObservation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "ip" TEXT,
    "port" INTEGER NOT NULL,
    "transport" TEXT NOT NULL DEFAULT 'tcp',
    "service" TEXT,
    "product" TEXT,
    "version" TEXT,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "sensitiveClass" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ServiceObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "HttpExposureSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "status" INTEGER,
    "title" TEXT,
    "headers" JSONB NOT NULL DEFAULT '{}',
    "redirectTarget" TEXT,
    "technologies" JSONB NOT NULL DEFAULT '[]',
    "certificateFingerprint" TEXT,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "HttpExposureSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TechnologyObservation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "technology" TEXT NOT NULL,
    "normalizedName" TEXT NOT NULL,
    "version" TEXT,
    "category" TEXT NOT NULL DEFAULT 'OTHER',
    "confidence" TEXT NOT NULL DEFAULT 'LOW',
    "sources" JSONB NOT NULL DEFAULT '[]',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TechnologyObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmAssetRelationship" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "fromType" TEXT NOT NULL,
    "fromId" TEXT NOT NULL,
    "toType" TEXT NOT NULL,
    "toId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "source" TEXT NOT NULL,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmAssetRelationship_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssetOwnershipRule" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT,
    "ruleType" TEXT NOT NULL,
    "pattern" TEXT NOT NULL,
    "ownershipStatus" TEXT NOT NULL DEFAULT 'LIKELY',
    "technicalOwner" TEXT,
    "team" TEXT,
    "application" TEXT,
    "businessUnit" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AssetOwnershipRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmScreenshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "storageKey" TEXT NOT NULL,
    "classification" TEXT NOT NULL DEFAULT 'RESTRICTED',
    "sha256" TEXT,
    "retentionUntil" TIMESTAMP(3),
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmScreenshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmDiscoveryRun" (
    "id" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "trigger" TEXT NOT NULL DEFAULT 'MANUAL',
    "candidatesFound" INTEGER NOT NULL DEFAULT 0,
    "candidatesNew" INTEGER NOT NULL DEFAULT 0,
    "promoted" INTEGER NOT NULL DEFAULT 0,
    "coverage" JSONB NOT NULL DEFAULT '{}',
    "errors" JSONB NOT NULL DEFAULT '[]',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "EasmDiscoveryRun_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmAdapterRunResult" (
    "id" TEXT NOT NULL,
    "runId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "adapter" TEXT NOT NULL,
    "version" TEXT,
    "status" TEXT NOT NULL,
    "durationMs" INTEGER NOT NULL DEFAULT 0,
    "resultCount" INTEGER NOT NULL DEFAULT 0,
    "errorClass" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmAdapterRunResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmDriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "candidateId" TEXT,
    "assetIdentity" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "before" JSONB,
    "after" JSONB,
    "severity" TEXT NOT NULL DEFAULT 'LOW',
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.8,
    "fingerprint" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "evidence" JSONB NOT NULL DEFAULT '{}',
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmDriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmBaseline" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "snapshot" JSONB NOT NULL DEFAULT '{}',
    "contentHash" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmBaseline_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EasmReportSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "programId" TEXT,
    "type" TEXT NOT NULL,
    "content" JSONB NOT NULL DEFAULT '{}',
    "contentHash" TEXT NOT NULL,
    "generatedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EasmReportSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "EasmProgram_workspaceId_status_idx" ON "EasmProgram"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "EasmRootAsset_workspaceId_programId_idx" ON "EasmRootAsset"("workspaceId", "programId");

-- CreateIndex
CREATE UNIQUE INDEX "EasmRootAsset_programId_type_value_key" ON "EasmRootAsset"("programId", "type", "value");

-- CreateIndex
CREATE UNIQUE INDEX "EasmDiscoveryPolicy_programId_key" ON "EasmDiscoveryPolicy"("programId");

-- CreateIndex
CREATE INDEX "EasmDiscoveryPolicy_workspaceId_idx" ON "EasmDiscoveryPolicy"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "EasmServiceDiscoveryProfile_programId_key" ON "EasmServiceDiscoveryProfile"("programId");

-- CreateIndex
CREATE INDEX "EasmServiceDiscoveryProfile_workspaceId_idx" ON "EasmServiceDiscoveryProfile"("workspaceId");

-- CreateIndex
CREATE INDEX "EasmAssetCandidate_workspaceId_status_idx" ON "EasmAssetCandidate"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "EasmAssetCandidate_workspaceId_ownershipStatus_idx" ON "EasmAssetCandidate"("workspaceId", "ownershipStatus");

-- CreateIndex
CREATE INDEX "EasmAssetCandidate_workspaceId_exposureState_idx" ON "EasmAssetCandidate"("workspaceId", "exposureState");

-- CreateIndex
CREATE UNIQUE INDEX "EasmAssetCandidate_programId_normalizedValue_key" ON "EasmAssetCandidate"("programId", "normalizedValue");

-- CreateIndex
CREATE INDEX "AssetDiscoveryObservation_workspaceId_candidateId_idx" ON "AssetDiscoveryObservation"("workspaceId", "candidateId");

-- CreateIndex
CREATE INDEX "AssetDiscoveryObservation_workspaceId_observedAt_idx" ON "AssetDiscoveryObservation"("workspaceId", "observedAt");

-- CreateIndex
CREATE INDEX "EasmOwnershipEvidence_workspaceId_candidateId_idx" ON "EasmOwnershipEvidence"("workspaceId", "candidateId");

-- CreateIndex
CREATE INDEX "DnsSnapshot_workspaceId_domain_observedAt_idx" ON "DnsSnapshot"("workspaceId", "domain", "observedAt");

-- CreateIndex
CREATE INDEX "DnsSnapshot_workspaceId_candidateId_idx" ON "DnsSnapshot"("workspaceId", "candidateId");

-- CreateIndex
CREATE INDEX "DanglingDnsCandidate_workspaceId_status_idx" ON "DanglingDnsCandidate"("workspaceId", "status");

-- CreateIndex
CREATE INDEX "EasmCertificate_workspaceId_state_idx" ON "EasmCertificate"("workspaceId", "state");

-- CreateIndex
CREATE UNIQUE INDEX "EasmCertificate_workspaceId_fingerprint_key" ON "EasmCertificate"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "EasmCertificateObservation_workspaceId_certificateId_idx" ON "EasmCertificateObservation"("workspaceId", "certificateId");

-- CreateIndex
CREATE INDEX "EasmCertificateObservation_workspaceId_host_idx" ON "EasmCertificateObservation"("workspaceId", "host");

-- CreateIndex
CREATE INDEX "HostExposureSnapshot_workspaceId_candidateId_capturedAt_idx" ON "HostExposureSnapshot"("workspaceId", "candidateId", "capturedAt");

-- CreateIndex
CREATE INDEX "ServiceObservation_workspaceId_candidateId_idx" ON "ServiceObservation"("workspaceId", "candidateId");

-- CreateIndex
CREATE UNIQUE INDEX "ServiceObservation_candidateId_port_transport_key" ON "ServiceObservation"("candidateId", "port", "transport");

-- CreateIndex
CREATE INDEX "HttpExposureSnapshot_workspaceId_candidateId_capturedAt_idx" ON "HttpExposureSnapshot"("workspaceId", "candidateId", "capturedAt");

-- CreateIndex
CREATE INDEX "TechnologyObservation_workspaceId_candidateId_idx" ON "TechnologyObservation"("workspaceId", "candidateId");

-- CreateIndex
CREATE UNIQUE INDEX "TechnologyObservation_candidateId_normalizedName_key" ON "TechnologyObservation"("candidateId", "normalizedName");

-- CreateIndex
CREATE INDEX "EasmAssetRelationship_workspaceId_programId_idx" ON "EasmAssetRelationship"("workspaceId", "programId");

-- CreateIndex
CREATE UNIQUE INDEX "EasmAssetRelationship_workspaceId_fromId_toId_kind_key" ON "EasmAssetRelationship"("workspaceId", "fromId", "toId", "kind");

-- CreateIndex
CREATE INDEX "AssetOwnershipRule_workspaceId_programId_idx" ON "AssetOwnershipRule"("workspaceId", "programId");

-- CreateIndex
CREATE INDEX "EasmScreenshot_workspaceId_candidateId_idx" ON "EasmScreenshot"("workspaceId", "candidateId");

-- CreateIndex
CREATE INDEX "EasmDiscoveryRun_workspaceId_programId_startedAt_idx" ON "EasmDiscoveryRun"("workspaceId", "programId", "startedAt");

-- CreateIndex
CREATE INDEX "EasmAdapterRunResult_workspaceId_runId_idx" ON "EasmAdapterRunResult"("workspaceId", "runId");

-- CreateIndex
CREATE INDEX "EasmDriftEvent_workspaceId_programId_detectedAt_idx" ON "EasmDriftEvent"("workspaceId", "programId", "detectedAt");

-- CreateIndex
CREATE INDEX "EasmDriftEvent_workspaceId_fingerprint_idx" ON "EasmDriftEvent"("workspaceId", "fingerprint");

-- CreateIndex
CREATE INDEX "EasmBaseline_workspaceId_programId_idx" ON "EasmBaseline"("workspaceId", "programId");

-- CreateIndex
CREATE UNIQUE INDEX "EasmBaseline_programId_version_key" ON "EasmBaseline"("programId", "version");

-- CreateIndex
CREATE INDEX "EasmReportSnapshot_workspaceId_type_createdAt_idx" ON "EasmReportSnapshot"("workspaceId", "type", "createdAt");

