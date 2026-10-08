-- CreateEnum
CREATE TYPE "ProductMode" AS ENUM ('COMMUNITY', 'SELF_HOSTED', 'SAAS', 'ENTERPRISE');

-- CreateEnum
CREATE TYPE "ProductPlanStatus" AS ENUM ('DRAFT', 'ACTIVE', 'DEPRECATED', 'RETIRED');

-- CreateEnum
CREATE TYPE "SubscriptionStatus" AS ENUM ('TRIALING', 'ACTIVE', 'PAST_DUE', 'SUSPENDED', 'CANCELLED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "ProductTrialStatus" AS ENUM ('ACTIVE', 'EXPIRED', 'CONVERTED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "QuotaReservationStatus" AS ENUM ('RESERVED', 'CONSUMED', 'RELEASED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "SupportAccessStatus" AS ENUM ('PENDING_APPROVAL', 'ACTIVE', 'EXPIRED', 'ENDED', 'REVOKED');

-- CreateEnum
CREATE TYPE "OrganizationLifecycleStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'CANCELLATION_PENDING', 'CANCELLED', 'RETENTION', 'DELETION_PENDING', 'DELETED');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'PLAN_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'PLAN_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'PLAN_ACTIVATED';
ALTER TYPE "AuditAction" ADD VALUE 'SUBSCRIPTION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SUBSCRIPTION_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'SUBSCRIPTION_CANCELLED';
ALTER TYPE "AuditAction" ADD VALUE 'TRIAL_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'TRIAL_EXPIRED';
ALTER TYPE "AuditAction" ADD VALUE 'LICENSE_INSTALLED';
ALTER TYPE "AuditAction" ADD VALUE 'LICENSE_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'LICENSE_EXPIRED';
ALTER TYPE "AuditAction" ADD VALUE 'QUOTA_EXCEEDED';
ALTER TYPE "AuditAction" ADD VALUE 'QUOTA_OVERRIDE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'BILLING_WEBHOOK_RECEIVED';
ALTER TYPE "AuditAction" ADD VALUE 'BILLING_WEBHOOK_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'ORGANIZATION_PROVISIONED';
ALTER TYPE "AuditAction" ADD VALUE 'ORGANIZATION_SUSPENDED';
ALTER TYPE "AuditAction" ADD VALUE 'ORGANIZATION_REACTIVATED';
ALTER TYPE "AuditAction" ADD VALUE 'ORGANIZATION_CANCELLATION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'ORGANIZATION_DELETION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'SUPPORT_ACCESS_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'SUPPORT_ACCESS_ENDED';

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "isDemo" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "legalHold" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "lifecycleStatus" "OrganizationLifecycleStatus" NOT NULL DEFAULT 'ACTIVE',
ADD COLUMN     "retentionUntil" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "isPlatformAdmin" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "ProductPlan" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "status" "ProductPlanStatus" NOT NULL DEFAULT 'DRAFT',
    "productMode" "ProductMode" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProductPlan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PlanVersion" (
    "id" TEXT NOT NULL,
    "planId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "quotas" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PlanVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PlanEntitlement" (
    "id" TEXT NOT NULL,
    "planVersionId" TEXT NOT NULL,
    "featureKey" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "limit" INTEGER,
    "configuration" JSONB,

    CONSTRAINT "PlanEntitlement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Subscription" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "planVersionId" TEXT NOT NULL,
    "status" "SubscriptionStatus" NOT NULL DEFAULT 'ACTIVE',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "currentPeriodStart" TIMESTAMP(3) NOT NULL,
    "currentPeriodEnd" TIMESTAMP(3) NOT NULL,
    "trialEndsAt" TIMESTAMP(3),
    "cancelAtPeriodEnd" BOOLEAN NOT NULL DEFAULT false,
    "cancelledAt" TIMESTAMP(3),
    "externalBillingReference" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Subscription_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BillingEvent" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT,
    "provider" TEXT NOT NULL,
    "externalEventId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "processedAt" TIMESTAMP(3),
    "error" TEXT,

    CONSTRAINT "BillingEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BillingInvoiceReference" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "externalInvoiceId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "currency" TEXT,
    "amountCents" INTEGER,
    "periodStart" TIMESTAMP(3),
    "periodEnd" TIMESTAMP(3),
    "hostedInvoiceRef" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BillingInvoiceReference_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProductLicense" (
    "id" TEXT NOT NULL,
    "licenseId" TEXT NOT NULL,
    "organizationId" TEXT,
    "organization" TEXT NOT NULL,
    "edition" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL,
    "validFrom" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "entitlements" JSONB NOT NULL,
    "limits" JSONB NOT NULL,
    "signature" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "installedById" TEXT,
    "installedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProductLicense_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UsageEvent" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT,
    "metric" TEXT NOT NULL,
    "quantity" DOUBLE PRECISION NOT NULL DEFAULT 1,
    "source" TEXT NOT NULL,
    "reference" TEXT,
    "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "idempotencyKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UsageEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UsageAggregate" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "metric" TEXT NOT NULL,
    "granularity" TEXT NOT NULL,
    "periodStart" TIMESTAMP(3) NOT NULL,
    "quantity" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UsageAggregate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "QuotaPolicy" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "dimension" TEXT NOT NULL,
    "limit" INTEGER,
    "period" TEXT NOT NULL DEFAULT 'MONTHLY',
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "QuotaPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "QuotaReservation" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "dimension" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL DEFAULT 1,
    "status" "QuotaReservationStatus" NOT NULL DEFAULT 'RESERVED',
    "reference" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "QuotaReservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "QuotaOverride" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "metric" TEXT NOT NULL,
    "newLimit" INTEGER NOT NULL,
    "reason" TEXT NOT NULL,
    "approvedById" TEXT NOT NULL,
    "startsAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "QuotaOverride_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProductTrial" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "planVersionId" TEXT NOT NULL,
    "status" "ProductTrialStatus" NOT NULL DEFAULT 'ACTIVE',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "conversionStatus" TEXT NOT NULL DEFAULT 'NONE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProductTrial_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrganizationOnboarding" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'IN_PROGRESS',
    "currentStep" TEXT NOT NULL DEFAULT 'WELCOME',
    "completedSteps" JSONB NOT NULL DEFAULT '[]',
    "authorizationAttestedAt" TIMESTAMP(3),
    "authorizationAttestedById" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrganizationOnboarding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmailVerificationToken" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailVerificationToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SupportAccessSession" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "operatorId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "scope" JSONB NOT NULL,
    "status" "SupportAccessStatus" NOT NULL DEFAULT 'PENDING_APPROVAL',
    "tenantApproved" BOOLEAN NOT NULL DEFAULT false,
    "approvedById" TEXT,
    "startedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "endedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SupportAccessSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeploymentRegion" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "dataResidencyClass" TEXT NOT NULL DEFAULT 'STANDARD',
    "capabilities" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DeploymentRegion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProductAnalyticsEvent" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT,
    "type" TEXT NOT NULL,
    "properties" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ProductAnalyticsEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ProductPlan_code_key" ON "ProductPlan"("code");

-- CreateIndex
CREATE INDEX "PlanVersion_planId_idx" ON "PlanVersion"("planId");

-- CreateIndex
CREATE UNIQUE INDEX "PlanVersion_planId_version_key" ON "PlanVersion"("planId", "version");

-- CreateIndex
CREATE INDEX "PlanEntitlement_planVersionId_idx" ON "PlanEntitlement"("planVersionId");

-- CreateIndex
CREATE UNIQUE INDEX "PlanEntitlement_planVersionId_featureKey_key" ON "PlanEntitlement"("planVersionId", "featureKey");

-- CreateIndex
CREATE INDEX "Subscription_organizationId_idx" ON "Subscription"("organizationId");

-- CreateIndex
CREATE INDEX "Subscription_status_idx" ON "Subscription"("status");

-- CreateIndex
CREATE INDEX "BillingEvent_organizationId_idx" ON "BillingEvent"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "BillingEvent_provider_externalEventId_key" ON "BillingEvent"("provider", "externalEventId");

-- CreateIndex
CREATE INDEX "BillingInvoiceReference_organizationId_idx" ON "BillingInvoiceReference"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "BillingInvoiceReference_provider_externalInvoiceId_key" ON "BillingInvoiceReference"("provider", "externalInvoiceId");

-- CreateIndex
CREATE UNIQUE INDEX "ProductLicense_licenseId_key" ON "ProductLicense"("licenseId");

-- CreateIndex
CREATE INDEX "ProductLicense_organizationId_idx" ON "ProductLicense"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "UsageEvent_idempotencyKey_key" ON "UsageEvent"("idempotencyKey");

-- CreateIndex
CREATE INDEX "UsageEvent_organizationId_metric_occurredAt_idx" ON "UsageEvent"("organizationId", "metric", "occurredAt");

-- CreateIndex
CREATE INDEX "UsageAggregate_organizationId_metric_idx" ON "UsageAggregate"("organizationId", "metric");

-- CreateIndex
CREATE UNIQUE INDEX "UsageAggregate_organizationId_metric_granularity_periodStar_key" ON "UsageAggregate"("organizationId", "metric", "granularity", "periodStart");

-- CreateIndex
CREATE INDEX "QuotaPolicy_organizationId_idx" ON "QuotaPolicy"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "QuotaPolicy_organizationId_dimension_period_key" ON "QuotaPolicy"("organizationId", "dimension", "period");

-- CreateIndex
CREATE INDEX "QuotaReservation_organizationId_dimension_status_idx" ON "QuotaReservation"("organizationId", "dimension", "status");

-- CreateIndex
CREATE UNIQUE INDEX "QuotaReservation_organizationId_dimension_reference_key" ON "QuotaReservation"("organizationId", "dimension", "reference");

-- CreateIndex
CREATE INDEX "QuotaOverride_organizationId_metric_idx" ON "QuotaOverride"("organizationId", "metric");

-- CreateIndex
CREATE INDEX "ProductTrial_organizationId_idx" ON "ProductTrial"("organizationId");

-- CreateIndex
CREATE INDEX "ProductTrial_status_idx" ON "ProductTrial"("status");

-- CreateIndex
CREATE UNIQUE INDEX "OrganizationOnboarding_organizationId_key" ON "OrganizationOnboarding"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "EmailVerificationToken_tokenHash_key" ON "EmailVerificationToken"("tokenHash");

-- CreateIndex
CREATE INDEX "EmailVerificationToken_userId_idx" ON "EmailVerificationToken"("userId");

-- CreateIndex
CREATE INDEX "SupportAccessSession_organizationId_idx" ON "SupportAccessSession"("organizationId");

-- CreateIndex
CREATE INDEX "SupportAccessSession_operatorId_idx" ON "SupportAccessSession"("operatorId");

-- CreateIndex
CREATE UNIQUE INDEX "DeploymentRegion_code_key" ON "DeploymentRegion"("code");

-- CreateIndex
CREATE INDEX "ProductAnalyticsEvent_type_createdAt_idx" ON "ProductAnalyticsEvent"("type", "createdAt");

-- AddForeignKey
ALTER TABLE "PlanVersion" ADD CONSTRAINT "PlanVersion_planId_fkey" FOREIGN KEY ("planId") REFERENCES "ProductPlan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PlanEntitlement" ADD CONSTRAINT "PlanEntitlement_planVersionId_fkey" FOREIGN KEY ("planVersionId") REFERENCES "PlanVersion"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Subscription" ADD CONSTRAINT "Subscription_planVersionId_fkey" FOREIGN KEY ("planVersionId") REFERENCES "PlanVersion"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProductTrial" ADD CONSTRAINT "ProductTrial_planVersionId_fkey" FOREIGN KEY ("planVersionId") REFERENCES "PlanVersion"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

