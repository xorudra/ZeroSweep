-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "TargetType" ADD VALUE 'ACTIVE_DIRECTORY_DOMAIN';
ALTER TYPE "TargetType" ADD VALUE 'ACTIVE_DIRECTORY_FOREST';
ALTER TYPE "TargetType" ADD VALUE 'DOMAIN_CONTROLLER';
ALTER TYPE "TargetType" ADD VALUE 'LDAP_DIRECTORY';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssessmentProfile" ADD VALUE 'AD_INVENTORY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'AD_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'AD_COMPREHENSIVE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'ADCS_POSTURE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'SMB_POSTURE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'IDENTITY_GRAPH';
ALTER TYPE "AssessmentProfile" ADD VALUE 'ATTACK_PATH_ANALYSIS';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'DOMAIN_DISCOVERY';
ALTER TYPE "ScanStageType" ADD VALUE 'DIRECTORY_INVENTORY';
ALTER TYPE "ScanStageType" ADD VALUE 'LDAP_POSTURE';
ALTER TYPE "ScanStageType" ADD VALUE 'SMB_POSTURE';
ALTER TYPE "ScanStageType" ADD VALUE 'GRAPH_COLLECTION';
ALTER TYPE "ScanStageType" ADD VALUE 'PINGCASTLE_POSTURE';
ALTER TYPE "ScanStageType" ADD VALUE 'ADCS_POSTURE';
ALTER TYPE "ScanStageType" ADD VALUE 'ATTACK_PATH_ANALYSIS';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'AD_DOMAIN_REGISTERED';
ALTER TYPE "AuditAction" ADD VALUE 'AD_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'AD_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'DIRECTORY_SNAPSHOT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'PRIVILEGED_IDENTITY_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'AD_ATTACK_PATH_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'AD_TRUST_DISCOVERED';
ALTER TYPE "AuditAction" ADD VALUE 'ADCS_RISK_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'AD_DRIFT_DETECTED';
ALTER TYPE "AuditAction" ADD VALUE 'DIRECTORY_ARTIFACT_ACCESSED';
ALTER TYPE "AuditAction" ADD VALUE 'AD_OFFENSIVE_ACTION_BLOCKED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "directoryDomainId" TEXT,
ADD COLUMN     "directoryObjectId" TEXT;

-- AlterTable
ALTER TABLE "CredentialLease" ADD COLUMN     "directoryDomainId" TEXT,
ALTER COLUMN "cloudAccountId" DROP NOT NULL;

-- CreateTable
CREATE TABLE "ActiveDirectoryForest" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "rootDomain" TEXT NOT NULL,
    "functionalLevel" TEXT,
    "assessmentState" TEXT NOT NULL DEFAULT 'REGISTERED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ActiveDirectoryForest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ActiveDirectoryDomain" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "forestId" TEXT,
    "dnsName" TEXT NOT NULL,
    "netbiosName" TEXT,
    "domainSid" TEXT,
    "functionalLevel" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'HIGH',
    "status" TEXT NOT NULL DEFAULT 'REGISTERED',
    "credentialProfileId" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,
    "lastAssessmentAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ActiveDirectoryDomain_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectoryCredentialProfile" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "identityKind" TEXT NOT NULL DEFAULT 'READ_ONLY_DOMAIN',
    "credentialReference" TEXT,
    "status" TEXT NOT NULL DEFAULT 'REGISTERED',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DirectoryCredentialProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DomainController" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "assetId" TEXT,
    "hostname" TEXT NOT NULL,
    "dnsName" TEXT,
    "ipAddresses" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "osName" TEXT,
    "osVersion" TEXT,
    "services" JSONB NOT NULL DEFAULT '{}',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DomainController_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectorySnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "scanId" TEXT,
    "collectionProfile" TEXT NOT NULL,
    "collectorVersions" JSONB NOT NULL DEFAULT '{}',
    "objectCounts" JSONB NOT NULL DEFAULT '{}',
    "relationshipCount" INTEGER NOT NULL DEFAULT 0,
    "snapshotHash" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DirectorySnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectoryUser" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "objectId" TEXT NOT NULL,
    "samAccountName" TEXT NOT NULL,
    "displayName" TEXT,
    "userPrincipalName" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "isServiceAccount" BOOLEAN NOT NULL DEFAULT false,
    "passwordNeverExpires" BOOLEAN NOT NULL DEFAULT false,
    "passwordNotRequired" BOOLEAN NOT NULL DEFAULT false,
    "preauthNotRequired" BOOLEAN NOT NULL DEFAULT false,
    "spnPresent" BOOLEAN NOT NULL DEFAULT false,
    "spns" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "delegationType" TEXT NOT NULL DEFAULT 'NONE',
    "delegationTargets" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "privileged" BOOLEAN NOT NULL DEFAULT false,
    "privilegeEvidence" JSONB,
    "riskScore" DOUBLE PRECISION,
    "riskFactors" JSONB,
    "lastLogonAt" TIMESTAMP(3),
    "passwordLastSetAt" TIMESTAMP(3),
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DirectoryUser_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectoryComputer" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "assetId" TEXT,
    "objectId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "dnsName" TEXT,
    "osName" TEXT,
    "osVersion" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "isDomainController" BOOLEAN NOT NULL DEFAULT false,
    "delegationType" TEXT NOT NULL DEFAULT 'NONE',
    "delegationTargets" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "unconstrainedDelegation" BOOLEAN NOT NULL DEFAULT false,
    "riskScore" DOUBLE PRECISION,
    "riskFactors" JSONB,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DirectoryComputer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectoryGroup" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "objectId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "groupScope" TEXT NOT NULL DEFAULT 'GLOBAL',
    "groupType" TEXT NOT NULL DEFAULT 'SECURITY',
    "privilegeClass" TEXT NOT NULL DEFAULT 'STANDARD',
    "memberCount" INTEGER NOT NULL DEFAULT 0,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DirectoryGroup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectoryOrganizationalUnit" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "objectId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "distinguishedName" TEXT NOT NULL,
    "parentRef" TEXT,
    "linkedGpoIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DirectoryOrganizationalUnit_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GroupPolicyObject" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "objectId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "linkedTo" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "securityMetadata" JSONB NOT NULL DEFAULT '{}',
    "delegationMetadata" JSONB NOT NULL DEFAULT '{}',
    "lastModifiedAt" TIMESTAMP(3),
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GroupPolicyObject_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectoryTrust" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "targetDomainName" TEXT NOT NULL,
    "targetDomainId" TEXT,
    "direction" TEXT NOT NULL,
    "trustType" TEXT NOT NULL,
    "transitive" BOOLEAN NOT NULL DEFAULT true,
    "sidFilteringEnabled" BOOLEAN,
    "selectiveAuthentication" BOOLEAN,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DirectoryTrust_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectoryRelationship" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "snapshotId" TEXT,
    "fromType" TEXT NOT NULL,
    "fromRef" TEXT NOT NULL,
    "toType" TEXT NOT NULL,
    "toRef" TEXT NOT NULL,
    "relationship" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "confidence" TEXT NOT NULL DEFAULT 'MEDIUM',
    "evidenceRef" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DirectoryRelationship_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdAttackPath" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "scanId" TEXT,
    "title" TEXT NOT NULL,
    "steps" JSONB NOT NULL DEFAULT '[]',
    "status" TEXT NOT NULL DEFAULT 'THEORETICAL',
    "confidence" TEXT NOT NULL DEFAULT 'LOW',
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "riskFactors" JSONB NOT NULL DEFAULT '{}',
    "findingIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdAttackPath_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SmbShare" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT,
    "assetId" TEXT,
    "host" TEXT NOT NULL,
    "shareName" TEXT NOT NULL,
    "accessLevel" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "anonymousAccess" BOOLEAN,
    "smbDialect" TEXT,
    "signingRequired" BOOLEAN,
    "source" TEXT NOT NULL,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SmbShare_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CertificateAuthority" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "dnsName" TEXT,
    "enrollmentServices" JSONB NOT NULL DEFAULT '[]',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CertificateAuthority_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CertificateTemplate" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "caId" TEXT,
    "name" TEXT NOT NULL,
    "objectId" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "enrollmentPermissions" JSONB NOT NULL DEFAULT '{}',
    "subjectConfig" JSONB NOT NULL DEFAULT '{}',
    "authenticationEkus" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "managerApprovalRequired" BOOLEAN NOT NULL DEFAULT false,
    "authorizedSignaturesRequired" INTEGER NOT NULL DEFAULT 0,
    "issuanceRequirements" JSONB NOT NULL DEFAULT '{}',
    "riskClasses" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CertificateTemplate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdDriftEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "scanId" TEXT,
    "snapshotId" TEXT,
    "kind" TEXT NOT NULL,
    "objectRef" TEXT,
    "detail" TEXT NOT NULL DEFAULT '',
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdDriftEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DirectoryArtifact" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domainId" TEXT NOT NULL,
    "scanId" TEXT,
    "artifactKind" TEXT NOT NULL,
    "storageKey" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "sizeBytes" INTEGER NOT NULL DEFAULT 0,
    "sensitivity" TEXT NOT NULL DEFAULT 'HIGH',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DirectoryArtifact_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ActiveDirectoryForest_workspaceId_idx" ON "ActiveDirectoryForest"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "ActiveDirectoryForest_workspaceId_rootDomain_key" ON "ActiveDirectoryForest"("workspaceId", "rootDomain");

-- CreateIndex
CREATE INDEX "ActiveDirectoryDomain_workspaceId_idx" ON "ActiveDirectoryDomain"("workspaceId");

-- CreateIndex
CREATE INDEX "ActiveDirectoryDomain_forestId_idx" ON "ActiveDirectoryDomain"("forestId");

-- CreateIndex
CREATE UNIQUE INDEX "ActiveDirectoryDomain_workspaceId_dnsName_key" ON "ActiveDirectoryDomain"("workspaceId", "dnsName");

-- CreateIndex
CREATE INDEX "DirectoryCredentialProfile_workspaceId_idx" ON "DirectoryCredentialProfile"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "DirectoryCredentialProfile_workspaceId_name_key" ON "DirectoryCredentialProfile"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "DomainController_workspaceId_idx" ON "DomainController"("workspaceId");

-- CreateIndex
CREATE INDEX "DomainController_domainId_idx" ON "DomainController"("domainId");

-- CreateIndex
CREATE UNIQUE INDEX "DomainController_domainId_hostname_key" ON "DomainController"("domainId", "hostname");

-- CreateIndex
CREATE INDEX "DirectorySnapshot_workspaceId_idx" ON "DirectorySnapshot"("workspaceId");

-- CreateIndex
CREATE INDEX "DirectorySnapshot_domainId_idx" ON "DirectorySnapshot"("domainId");

-- CreateIndex
CREATE INDEX "DirectorySnapshot_scanId_idx" ON "DirectorySnapshot"("scanId");

-- CreateIndex
CREATE INDEX "DirectoryUser_workspaceId_idx" ON "DirectoryUser"("workspaceId");

-- CreateIndex
CREATE INDEX "DirectoryUser_domainId_privileged_idx" ON "DirectoryUser"("domainId", "privileged");

-- CreateIndex
CREATE UNIQUE INDEX "DirectoryUser_domainId_objectId_key" ON "DirectoryUser"("domainId", "objectId");

-- CreateIndex
CREATE INDEX "DirectoryComputer_workspaceId_idx" ON "DirectoryComputer"("workspaceId");

-- CreateIndex
CREATE INDEX "DirectoryComputer_domainId_idx" ON "DirectoryComputer"("domainId");

-- CreateIndex
CREATE UNIQUE INDEX "DirectoryComputer_domainId_objectId_key" ON "DirectoryComputer"("domainId", "objectId");

-- CreateIndex
CREATE INDEX "DirectoryGroup_workspaceId_idx" ON "DirectoryGroup"("workspaceId");

-- CreateIndex
CREATE INDEX "DirectoryGroup_domainId_privilegeClass_idx" ON "DirectoryGroup"("domainId", "privilegeClass");

-- CreateIndex
CREATE UNIQUE INDEX "DirectoryGroup_domainId_objectId_key" ON "DirectoryGroup"("domainId", "objectId");

-- CreateIndex
CREATE INDEX "DirectoryOrganizationalUnit_workspaceId_idx" ON "DirectoryOrganizationalUnit"("workspaceId");

-- CreateIndex
CREATE INDEX "DirectoryOrganizationalUnit_domainId_idx" ON "DirectoryOrganizationalUnit"("domainId");

-- CreateIndex
CREATE UNIQUE INDEX "DirectoryOrganizationalUnit_domainId_objectId_key" ON "DirectoryOrganizationalUnit"("domainId", "objectId");

-- CreateIndex
CREATE INDEX "GroupPolicyObject_workspaceId_idx" ON "GroupPolicyObject"("workspaceId");

-- CreateIndex
CREATE INDEX "GroupPolicyObject_domainId_idx" ON "GroupPolicyObject"("domainId");

-- CreateIndex
CREATE UNIQUE INDEX "GroupPolicyObject_domainId_objectId_key" ON "GroupPolicyObject"("domainId", "objectId");

-- CreateIndex
CREATE INDEX "DirectoryTrust_workspaceId_idx" ON "DirectoryTrust"("workspaceId");

-- CreateIndex
CREATE INDEX "DirectoryTrust_domainId_idx" ON "DirectoryTrust"("domainId");

-- CreateIndex
CREATE UNIQUE INDEX "DirectoryTrust_domainId_targetDomainName_key" ON "DirectoryTrust"("domainId", "targetDomainName");

-- CreateIndex
CREATE INDEX "DirectoryRelationship_workspaceId_idx" ON "DirectoryRelationship"("workspaceId");

-- CreateIndex
CREATE INDEX "DirectoryRelationship_domainId_idx" ON "DirectoryRelationship"("domainId");

-- CreateIndex
CREATE INDEX "DirectoryRelationship_domainId_relationship_idx" ON "DirectoryRelationship"("domainId", "relationship");

-- CreateIndex
CREATE UNIQUE INDEX "DirectoryRelationship_domainId_fromType_fromRef_relationshi_key" ON "DirectoryRelationship"("domainId", "fromType", "fromRef", "relationship", "toType", "toRef");

-- CreateIndex
CREATE INDEX "AdAttackPath_workspaceId_idx" ON "AdAttackPath"("workspaceId");

-- CreateIndex
CREATE INDEX "AdAttackPath_domainId_idx" ON "AdAttackPath"("domainId");

-- CreateIndex
CREATE INDEX "AdAttackPath_scanId_idx" ON "AdAttackPath"("scanId");

-- CreateIndex
CREATE INDEX "SmbShare_workspaceId_idx" ON "SmbShare"("workspaceId");

-- CreateIndex
CREATE INDEX "SmbShare_domainId_idx" ON "SmbShare"("domainId");

-- CreateIndex
CREATE UNIQUE INDEX "SmbShare_domainId_host_shareName_key" ON "SmbShare"("domainId", "host", "shareName");

-- CreateIndex
CREATE INDEX "CertificateAuthority_workspaceId_idx" ON "CertificateAuthority"("workspaceId");

-- CreateIndex
CREATE INDEX "CertificateAuthority_domainId_idx" ON "CertificateAuthority"("domainId");

-- CreateIndex
CREATE UNIQUE INDEX "CertificateAuthority_domainId_name_key" ON "CertificateAuthority"("domainId", "name");

-- CreateIndex
CREATE INDEX "CertificateTemplate_workspaceId_idx" ON "CertificateTemplate"("workspaceId");

-- CreateIndex
CREATE INDEX "CertificateTemplate_domainId_idx" ON "CertificateTemplate"("domainId");

-- CreateIndex
CREATE UNIQUE INDEX "CertificateTemplate_domainId_name_key" ON "CertificateTemplate"("domainId", "name");

-- CreateIndex
CREATE INDEX "AdDriftEvent_workspaceId_idx" ON "AdDriftEvent"("workspaceId");

-- CreateIndex
CREATE INDEX "AdDriftEvent_domainId_idx" ON "AdDriftEvent"("domainId");

-- CreateIndex
CREATE INDEX "AdDriftEvent_kind_idx" ON "AdDriftEvent"("kind");

-- CreateIndex
CREATE INDEX "DirectoryArtifact_workspaceId_idx" ON "DirectoryArtifact"("workspaceId");

-- CreateIndex
CREATE INDEX "DirectoryArtifact_domainId_idx" ON "DirectoryArtifact"("domainId");

-- CreateIndex
CREATE INDEX "Finding_directoryDomainId_idx" ON "Finding"("directoryDomainId");

-- CreateIndex
CREATE INDEX "Finding_directoryObjectId_idx" ON "Finding"("directoryObjectId");

-- CreateIndex
CREATE INDEX "CredentialLease_directoryDomainId_idx" ON "CredentialLease"("directoryDomainId");

-- AddForeignKey
ALTER TABLE "CredentialLease" ADD CONSTRAINT "CredentialLease_directoryDomainId_fkey" FOREIGN KEY ("directoryDomainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActiveDirectoryDomain" ADD CONSTRAINT "ActiveDirectoryDomain_forestId_fkey" FOREIGN KEY ("forestId") REFERENCES "ActiveDirectoryForest"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActiveDirectoryDomain" ADD CONSTRAINT "ActiveDirectoryDomain_credentialProfileId_fkey" FOREIGN KEY ("credentialProfileId") REFERENCES "DirectoryCredentialProfile"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DomainController" ADD CONSTRAINT "DomainController_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DirectorySnapshot" ADD CONSTRAINT "DirectorySnapshot_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DirectoryUser" ADD CONSTRAINT "DirectoryUser_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DirectoryComputer" ADD CONSTRAINT "DirectoryComputer_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DirectoryGroup" ADD CONSTRAINT "DirectoryGroup_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DirectoryOrganizationalUnit" ADD CONSTRAINT "DirectoryOrganizationalUnit_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GroupPolicyObject" ADD CONSTRAINT "GroupPolicyObject_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DirectoryTrust" ADD CONSTRAINT "DirectoryTrust_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DirectoryRelationship" ADD CONSTRAINT "DirectoryRelationship_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AdAttackPath" ADD CONSTRAINT "AdAttackPath_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SmbShare" ADD CONSTRAINT "SmbShare_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CertificateAuthority" ADD CONSTRAINT "CertificateAuthority_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CertificateTemplate" ADD CONSTRAINT "CertificateTemplate_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CertificateTemplate" ADD CONSTRAINT "CertificateTemplate_caId_fkey" FOREIGN KEY ("caId") REFERENCES "CertificateAuthority"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AdDriftEvent" ADD CONSTRAINT "AdDriftEvent_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DirectoryArtifact" ADD CONSTRAINT "DirectoryArtifact_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "ActiveDirectoryDomain"("id") ON DELETE CASCADE ON UPDATE CASCADE;

