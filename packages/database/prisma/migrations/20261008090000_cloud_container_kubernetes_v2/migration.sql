-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_ACCOUNT_CONNECTED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_ACCOUNT_CONNECTION_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_ASSESSMENT_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_ASSESSMENT_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_FINDING_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'CLOUD_BASELINE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTAINER_ASSESSMENT_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'CONTAINER_BASELINE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'KUBERNETES_CLUSTER_CONNECTED';
ALTER TYPE "AuditAction" ADD VALUE 'KUBERNETES_ASSESSMENT_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'KUBERNETES_FINDING_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'KUBERNETES_BASELINE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'KUBERNETES_RUNTIME_EVENT_INGESTED';
ALTER TYPE "AuditAction" ADD VALUE 'RUNTIME_EVENT_CORRELATED';

-- AlterTable
ALTER TABLE "CloudAccount" ADD COLUMN     "authorizationId" TEXT;

-- CreateTable
CREATE TABLE "CloudConnectionTest" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "result" TEXT NOT NULL,
    "limitations" JSONB NOT NULL DEFAULT '[]',
    "missingPermissions" JSONB NOT NULL DEFAULT '[]',
    "accountMatch" BOOLEAN NOT NULL DEFAULT true,
    "testedById" TEXT,
    "testedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CloudConnectionTest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudResourceSnapshot" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT NOT NULL,
    "cloudResourceId" TEXT NOT NULL,
    "runId" TEXT,
    "configuration" JSONB NOT NULL DEFAULT '{}',
    "configurationHash" TEXT NOT NULL,
    "exposure" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CloudResourceSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudV2AssessmentRun" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "cloudAccountId" TEXT,
    "clusterId" TEXT,
    "imageId" TEXT,
    "scanId" TEXT,
    "pipeline" JSONB NOT NULL DEFAULT '[]',
    "status" TEXT NOT NULL DEFAULT 'RUNNING',
    "blockedReason" TEXT,
    "startedById" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "CloudV2AssessmentRun_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudSecurityBaseline" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "cloudAccountId" TEXT,
    "provider" TEXT,
    "version" INTEGER NOT NULL,
    "rules" JSONB NOT NULL DEFAULT '[]',
    "hash" TEXT NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CloudSecurityBaseline_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ContainerSecurityBaseline" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "registryId" TEXT,
    "version" INTEGER NOT NULL,
    "rules" JSONB NOT NULL DEFAULT '[]',
    "hash" TEXT NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ContainerSecurityBaseline_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KubernetesSecurityBaseline" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "clusterId" TEXT,
    "version" INTEGER NOT NULL,
    "rules" JSONB NOT NULL DEFAULT '[]',
    "hash" TEXT NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "KubernetesSecurityBaseline_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CloudSecurityCoverage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "runId" TEXT,
    "cloudAccountId" TEXT NOT NULL,
    "accountsCovered" INTEGER NOT NULL DEFAULT 0,
    "regionsCovered" INTEGER NOT NULL DEFAULT 0,
    "regionsAuthorized" INTEGER NOT NULL DEFAULT 0,
    "servicesCovered" INTEGER NOT NULL DEFAULT 0,
    "resourcesCovered" INTEGER NOT NULL DEFAULT 0,
    "iamIdentities" INTEGER NOT NULL DEFAULT 0,
    "postureChecks" INTEGER NOT NULL DEFAULT 0,
    "gaps" JSONB NOT NULL DEFAULT '[]',
    "completion" TEXT NOT NULL DEFAULT 'COMPLETED_WITH_GAPS',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CloudSecurityCoverage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ContainerSecurityCoverage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "runId" TEXT,
    "imageId" TEXT,
    "registriesCovered" INTEGER NOT NULL DEFAULT 0,
    "repositoriesCovered" INTEGER NOT NULL DEFAULT 0,
    "imagesCovered" INTEGER NOT NULL DEFAULT 0,
    "sbomCoverage" DOUBLE PRECISION,
    "vulnerabilityCoverage" DOUBLE PRECISION,
    "deploymentCorrelated" INTEGER NOT NULL DEFAULT 0,
    "gaps" JSONB NOT NULL DEFAULT '[]',
    "completion" TEXT NOT NULL DEFAULT 'COMPLETED_WITH_GAPS',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ContainerSecurityCoverage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KubernetesSecurityCoverage" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "runId" TEXT,
    "clusterId" TEXT NOT NULL,
    "namespacesCovered" INTEGER NOT NULL DEFAULT 0,
    "workloadsCovered" INTEGER NOT NULL DEFAULT 0,
    "rbacSubjects" INTEGER NOT NULL DEFAULT 0,
    "benchmarkChecks" INTEGER NOT NULL DEFAULT 0,
    "imagesCorrelated" INTEGER NOT NULL DEFAULT 0,
    "runtimeTelemetry" BOOLEAN NOT NULL DEFAULT false,
    "gaps" JSONB NOT NULL DEFAULT '[]',
    "completion" TEXT NOT NULL DEFAULT 'COMPLETED_WITH_GAPS',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "KubernetesSecurityCoverage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KubernetesRole" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "clusterId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "namespace" TEXT,
    "name" TEXT NOT NULL,
    "rules" JSONB NOT NULL DEFAULT '[]',
    "labels" JSONB NOT NULL DEFAULT '{}',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KubernetesRole_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KubernetesRoleBinding" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "clusterId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "namespace" TEXT,
    "name" TEXT NOT NULL,
    "roleKind" TEXT NOT NULL,
    "roleName" TEXT NOT NULL,
    "subjects" JSONB NOT NULL DEFAULT '[]',
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KubernetesRoleBinding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RuntimeEventCorrelation" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "clusterId" TEXT,
    "workloadRef" TEXT,
    "imageRef" TEXT,
    "imageId" TEXT,
    "findingIds" JSONB NOT NULL DEFAULT '[]',
    "confidence" TEXT NOT NULL DEFAULT 'LOW',
    "socAlertLinked" BOOLEAN NOT NULL DEFAULT false,
    "detail" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RuntimeEventCorrelation_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CloudConnectionTest_workspaceId_idx" ON "CloudConnectionTest"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudConnectionTest_cloudAccountId_testedAt_idx" ON "CloudConnectionTest"("cloudAccountId", "testedAt");

-- CreateIndex
CREATE INDEX "CloudResourceSnapshot_workspaceId_idx" ON "CloudResourceSnapshot"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudResourceSnapshot_cloudResourceId_capturedAt_idx" ON "CloudResourceSnapshot"("cloudResourceId", "capturedAt");

-- CreateIndex
CREATE INDEX "CloudResourceSnapshot_cloudAccountId_capturedAt_idx" ON "CloudResourceSnapshot"("cloudAccountId", "capturedAt");

-- CreateIndex
CREATE INDEX "CloudV2AssessmentRun_workspaceId_domain_idx" ON "CloudV2AssessmentRun"("workspaceId", "domain");

-- CreateIndex
CREATE INDEX "CloudV2AssessmentRun_cloudAccountId_idx" ON "CloudV2AssessmentRun"("cloudAccountId");

-- CreateIndex
CREATE INDEX "CloudV2AssessmentRun_clusterId_idx" ON "CloudV2AssessmentRun"("clusterId");

-- CreateIndex
CREATE INDEX "CloudV2AssessmentRun_imageId_idx" ON "CloudV2AssessmentRun"("imageId");

-- CreateIndex
CREATE INDEX "CloudSecurityBaseline_workspaceId_createdAt_idx" ON "CloudSecurityBaseline"("workspaceId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "CloudSecurityBaseline_workspaceId_cloudAccountId_provider_v_key" ON "CloudSecurityBaseline"("workspaceId", "cloudAccountId", "provider", "version");

-- CreateIndex
CREATE INDEX "ContainerSecurityBaseline_workspaceId_createdAt_idx" ON "ContainerSecurityBaseline"("workspaceId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ContainerSecurityBaseline_workspaceId_registryId_version_key" ON "ContainerSecurityBaseline"("workspaceId", "registryId", "version");

-- CreateIndex
CREATE INDEX "KubernetesSecurityBaseline_workspaceId_createdAt_idx" ON "KubernetesSecurityBaseline"("workspaceId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "KubernetesSecurityBaseline_workspaceId_clusterId_version_key" ON "KubernetesSecurityBaseline"("workspaceId", "clusterId", "version");

-- CreateIndex
CREATE UNIQUE INDEX "CloudSecurityCoverage_runId_key" ON "CloudSecurityCoverage"("runId");

-- CreateIndex
CREATE INDEX "CloudSecurityCoverage_workspaceId_idx" ON "CloudSecurityCoverage"("workspaceId");

-- CreateIndex
CREATE INDEX "CloudSecurityCoverage_cloudAccountId_createdAt_idx" ON "CloudSecurityCoverage"("cloudAccountId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ContainerSecurityCoverage_runId_key" ON "ContainerSecurityCoverage"("runId");

-- CreateIndex
CREATE INDEX "ContainerSecurityCoverage_workspaceId_idx" ON "ContainerSecurityCoverage"("workspaceId");

-- CreateIndex
CREATE INDEX "ContainerSecurityCoverage_imageId_createdAt_idx" ON "ContainerSecurityCoverage"("imageId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "KubernetesSecurityCoverage_runId_key" ON "KubernetesSecurityCoverage"("runId");

-- CreateIndex
CREATE INDEX "KubernetesSecurityCoverage_workspaceId_idx" ON "KubernetesSecurityCoverage"("workspaceId");

-- CreateIndex
CREATE INDEX "KubernetesSecurityCoverage_clusterId_createdAt_idx" ON "KubernetesSecurityCoverage"("clusterId", "createdAt");

-- CreateIndex
CREATE INDEX "KubernetesRole_workspaceId_idx" ON "KubernetesRole"("workspaceId");

-- CreateIndex
CREATE INDEX "KubernetesRole_clusterId_idx" ON "KubernetesRole"("clusterId");

-- CreateIndex
CREATE UNIQUE INDEX "KubernetesRole_clusterId_kind_namespace_name_key" ON "KubernetesRole"("clusterId", "kind", "namespace", "name");

-- CreateIndex
CREATE INDEX "KubernetesRoleBinding_workspaceId_idx" ON "KubernetesRoleBinding"("workspaceId");

-- CreateIndex
CREATE INDEX "KubernetesRoleBinding_clusterId_idx" ON "KubernetesRoleBinding"("clusterId");

-- CreateIndex
CREATE UNIQUE INDEX "KubernetesRoleBinding_clusterId_kind_namespace_name_key" ON "KubernetesRoleBinding"("clusterId", "kind", "namespace", "name");

-- CreateIndex
CREATE UNIQUE INDEX "RuntimeEventCorrelation_eventId_key" ON "RuntimeEventCorrelation"("eventId");

-- CreateIndex
CREATE INDEX "RuntimeEventCorrelation_workspaceId_idx" ON "RuntimeEventCorrelation"("workspaceId");

-- CreateIndex
CREATE INDEX "RuntimeEventCorrelation_clusterId_idx" ON "RuntimeEventCorrelation"("clusterId");

-- AddForeignKey
ALTER TABLE "CloudConnectionTest" ADD CONSTRAINT "CloudConnectionTest_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CloudResourceSnapshot" ADD CONSTRAINT "CloudResourceSnapshot_cloudAccountId_fkey" FOREIGN KEY ("cloudAccountId") REFERENCES "CloudAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CloudResourceSnapshot" ADD CONSTRAINT "CloudResourceSnapshot_cloudResourceId_fkey" FOREIGN KEY ("cloudResourceId") REFERENCES "CloudResource"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "KubernetesRole" ADD CONSTRAINT "KubernetesRole_clusterId_fkey" FOREIGN KEY ("clusterId") REFERENCES "KubernetesCluster"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "KubernetesRoleBinding" ADD CONSTRAINT "KubernetesRoleBinding_clusterId_fkey" FOREIGN KEY ("clusterId") REFERENCES "KubernetesCluster"("id") ON DELETE CASCADE ON UPDATE CASCADE;

