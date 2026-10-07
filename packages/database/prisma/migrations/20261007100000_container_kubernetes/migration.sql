-- CreateEnum
CREATE TYPE "ControlAssessmentStatus" AS ENUM ('PASS', 'FAIL', 'WARN', 'NOT_APPLICABLE', 'UNKNOWN');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "TargetType" ADD VALUE 'CONTAINER_REGISTRY';
ALTER TYPE "TargetType" ADD VALUE 'DOCKER_HOST';
ALTER TYPE "TargetType" ADD VALUE 'KUBERNETES_CLUSTER';
ALTER TYPE "TargetType" ADD VALUE 'KUBERNETES_MANIFEST';
ALTER TYPE "TargetType" ADD VALUE 'HELM_CHART';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssessmentProfile" ADD VALUE 'CONTAINER_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'CONTAINER_COMPREHENSIVE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'SBOM_ONLY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'IMAGE_VULNERABILITIES_ONLY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'CONTAINER_MISCONFIG_ONLY';
ALTER TYPE "AssessmentProfile" ADD VALUE 'KUBERNETES_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'KUBERNETES_COMPREHENSIVE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'DOCKER_HOST_BASELINE';
ALTER TYPE "AssessmentProfile" ADD VALUE 'CLOUD_NATIVE_FULL';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'IMAGE_RESOLUTION';
ALTER TYPE "ScanStageType" ADD VALUE 'IMAGE_VULNERABILITY_SCAN';
ALTER TYPE "ScanStageType" ADD VALUE 'MANIFEST_SCAN';
ALTER TYPE "ScanStageType" ADD VALUE 'CLUSTER_INVENTORY';
ALTER TYPE "ScanStageType" ADD VALUE 'KUBERNETES_POSTURE';
ALTER TYPE "ScanStageType" ADD VALUE 'DOCKER_POSTURE';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'CONTAINER_IMAGE_REGISTERED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTAINER_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTAINER_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'KUBERNETES_CLUSTER_REGISTERED';
ALTER TYPE "AuditAction" ADD VALUE 'KUBERNETES_SCAN_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'KUBERNETES_SCAN_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'DOCKER_POSTURE_ASSESSED';
ALTER TYPE "AuditAction" ADD VALUE 'COMPLIANCE_ASSESSED';
ALTER TYPE "AuditAction" ADD VALUE 'RUNTIME_EVENT_INGESTED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_NATIVE_ARTIFACT_ACCESSED';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "clusterRef" TEXT,
ADD COLUMN     "containerName" TEXT,
ADD COLUMN     "controlId" TEXT,
ADD COLUMN     "imageDigest" TEXT,
ADD COLUMN     "imageRef" TEXT,
ADD COLUMN     "namespace" TEXT,
ADD COLUMN     "origin" TEXT,
ADD COLUMN     "resourceKind" TEXT,
ADD COLUMN     "resourceName" TEXT;

-- AlterTable
ALTER TABLE "SoftwareComponent" ADD COLUMN     "imageId" TEXT,
ALTER COLUMN "snapshotId" DROP NOT NULL;

-- AlterTable
ALTER TABLE "SoftwareBillOfMaterials" ADD COLUMN     "imageId" TEXT,
ALTER COLUMN "snapshotId" DROP NOT NULL;

-- CreateTable
CREATE TABLE "ContainerRegistry" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "provider" TEXT NOT NULL DEFAULT 'GENERIC',
    "credentialReference" TEXT,
    "approved" BOOLEAN NOT NULL DEFAULT false,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ContainerRegistry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ContainerImage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "registryId" TEXT,
    "reference" TEXT NOT NULL,
    "registry" TEXT NOT NULL,
    "repository" TEXT NOT NULL,
    "tag" TEXT,
    "digest" TEXT,
    "platform" TEXT,
    "architecture" TEXT,
    "os" TEXT,
    "source" TEXT NOT NULL DEFAULT 'MANUAL',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ContainerImage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ContainerImageSnapshot" (
    "id" TEXT NOT NULL,
    "imageId" TEXT NOT NULL,
    "scanId" TEXT,
    "digest" TEXT NOT NULL,
    "previousDigest" TEXT,
    "drift" BOOLEAN NOT NULL DEFAULT false,
    "config" JSONB NOT NULL DEFAULT '{}',
    "layers" JSONB NOT NULL DEFAULT '[]',
    "baseImage" JSONB,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ContainerImageSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DockerHost" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "name" TEXT NOT NULL,
    "engineVersion" TEXT,
    "os" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "scanStatus" TEXT NOT NULL DEFAULT 'NOT_ASSESSED',
    "lastAssessmentAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DockerHost_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KubernetesCluster" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "targetId" TEXT,
    "name" TEXT NOT NULL,
    "apiServerReference" TEXT NOT NULL,
    "version" TEXT,
    "provider" TEXT NOT NULL DEFAULT 'GENERIC',
    "credentialReference" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "criticality" TEXT NOT NULL DEFAULT 'MEDIUM',
    "lastAssessmentAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KubernetesCluster_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KubernetesWorkload" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "clusterId" TEXT NOT NULL,
    "scanId" TEXT,
    "kind" TEXT NOT NULL,
    "namespace" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "replicas" INTEGER,
    "serviceAccount" TEXT,
    "images" JSONB NOT NULL DEFAULT '[]',
    "securityContext" JSONB NOT NULL DEFAULT '{}',
    "exposure" TEXT NOT NULL DEFAULT 'CLUSTER_INTERNAL',
    "labels" JSONB NOT NULL DEFAULT '{}',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KubernetesWorkload_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "InfrastructureManifest" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "repositoryId" TEXT,
    "snapshotId" TEXT,
    "scanId" TEXT,
    "filePath" TEXT NOT NULL,
    "manifestType" TEXT NOT NULL,
    "resourceCount" INTEGER NOT NULL DEFAULT 0,
    "checksum" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'SOURCE_SNAPSHOT',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "InfrastructureManifest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ComplianceFramework" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "description" TEXT NOT NULL,

    CONSTRAINT "ComplianceFramework_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ComplianceControl" (
    "id" TEXT NOT NULL,
    "frameworkId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,

    CONSTRAINT "ComplianceControl_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlAssessment" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "scanId" TEXT,
    "frameworkKey" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "subjectRef" TEXT NOT NULL,
    "status" "ControlAssessmentStatus" NOT NULL,
    "evidence" TEXT NOT NULL DEFAULT '',
    "findingId" TEXT,
    "assessedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ControlAssessment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RuntimeSecurityEvent" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "clusterId" TEXT,
    "clusterName" TEXT,
    "node" TEXT,
    "namespace" TEXT,
    "pod" TEXT,
    "container" TEXT,
    "rule" TEXT NOT NULL,
    "priority" TEXT NOT NULL,
    "eventTime" TIMESTAMP(3) NOT NULL,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "source" TEXT NOT NULL DEFAULT 'FALCO',
    "artifactRef" TEXT,
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RuntimeSecurityEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ContainerRegistry_workspaceId_idx" ON "ContainerRegistry"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "ContainerRegistry_workspaceId_url_key" ON "ContainerRegistry"("workspaceId", "url");

-- CreateIndex
CREATE INDEX "ContainerImage_workspaceId_idx" ON "ContainerImage"("workspaceId");

-- CreateIndex
CREATE INDEX "ContainerImage_workspaceId_repository_idx" ON "ContainerImage"("workspaceId", "repository");

-- CreateIndex
CREATE INDEX "ContainerImage_digest_idx" ON "ContainerImage"("digest");

-- CreateIndex
CREATE UNIQUE INDEX "ContainerImage_workspaceId_registry_repository_digest_key" ON "ContainerImage"("workspaceId", "registry", "repository", "digest");

-- CreateIndex
CREATE INDEX "ContainerImageSnapshot_imageId_idx" ON "ContainerImageSnapshot"("imageId");

-- CreateIndex
CREATE INDEX "ContainerImageSnapshot_scanId_idx" ON "ContainerImageSnapshot"("scanId");

-- CreateIndex
CREATE INDEX "DockerHost_workspaceId_idx" ON "DockerHost"("workspaceId");

-- CreateIndex
CREATE INDEX "KubernetesCluster_workspaceId_idx" ON "KubernetesCluster"("workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "KubernetesCluster_workspaceId_name_key" ON "KubernetesCluster"("workspaceId", "name");

-- CreateIndex
CREATE INDEX "KubernetesWorkload_workspaceId_idx" ON "KubernetesWorkload"("workspaceId");

-- CreateIndex
CREATE INDEX "KubernetesWorkload_clusterId_idx" ON "KubernetesWorkload"("clusterId");

-- CreateIndex
CREATE UNIQUE INDEX "KubernetesWorkload_clusterId_kind_namespace_name_key" ON "KubernetesWorkload"("clusterId", "kind", "namespace", "name");

-- CreateIndex
CREATE INDEX "InfrastructureManifest_workspaceId_idx" ON "InfrastructureManifest"("workspaceId");

-- CreateIndex
CREATE INDEX "InfrastructureManifest_snapshotId_idx" ON "InfrastructureManifest"("snapshotId");

-- CreateIndex
CREATE UNIQUE INDEX "ComplianceFramework_key_key" ON "ComplianceFramework"("key");

-- CreateIndex
CREATE INDEX "ComplianceControl_frameworkId_idx" ON "ComplianceControl"("frameworkId");

-- CreateIndex
CREATE UNIQUE INDEX "ComplianceControl_frameworkId_controlId_key" ON "ComplianceControl"("frameworkId", "controlId");

-- CreateIndex
CREATE INDEX "ControlAssessment_workspaceId_idx" ON "ControlAssessment"("workspaceId");

-- CreateIndex
CREATE INDEX "ControlAssessment_scanId_idx" ON "ControlAssessment"("scanId");

-- CreateIndex
CREATE INDEX "ControlAssessment_frameworkKey_controlId_idx" ON "ControlAssessment"("frameworkKey", "controlId");

-- CreateIndex
CREATE INDEX "RuntimeSecurityEvent_workspaceId_idx" ON "RuntimeSecurityEvent"("workspaceId");

-- CreateIndex
CREATE INDEX "RuntimeSecurityEvent_clusterId_idx" ON "RuntimeSecurityEvent"("clusterId");

-- CreateIndex
CREATE INDEX "RuntimeSecurityEvent_eventTime_idx" ON "RuntimeSecurityEvent"("eventTime");

-- CreateIndex
CREATE INDEX "SoftwareComponent_imageId_idx" ON "SoftwareComponent"("imageId");

-- CreateIndex
CREATE UNIQUE INDEX "SoftwareComponent_imageId_purl_key" ON "SoftwareComponent"("imageId", "purl");

-- CreateIndex
CREATE INDEX "SoftwareBillOfMaterials_imageId_idx" ON "SoftwareBillOfMaterials"("imageId");

-- AddForeignKey
ALTER TABLE "SoftwareComponent" ADD CONSTRAINT "SoftwareComponent_imageId_fkey" FOREIGN KEY ("imageId") REFERENCES "ContainerImage"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoftwareBillOfMaterials" ADD CONSTRAINT "SoftwareBillOfMaterials_imageId_fkey" FOREIGN KEY ("imageId") REFERENCES "ContainerImage"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ContainerImage" ADD CONSTRAINT "ContainerImage_registryId_fkey" FOREIGN KEY ("registryId") REFERENCES "ContainerRegistry"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ContainerImageSnapshot" ADD CONSTRAINT "ContainerImageSnapshot_imageId_fkey" FOREIGN KEY ("imageId") REFERENCES "ContainerImage"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "KubernetesWorkload" ADD CONSTRAINT "KubernetesWorkload_clusterId_fkey" FOREIGN KEY ("clusterId") REFERENCES "KubernetesCluster"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ComplianceControl" ADD CONSTRAINT "ComplianceControl_frameworkId_fkey" FOREIGN KEY ("frameworkId") REFERENCES "ComplianceFramework"("id") ON DELETE CASCADE ON UPDATE CASCADE;

