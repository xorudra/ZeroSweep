-- CreateEnum
CREATE TYPE "PlatformBackupStatus" AS ENUM ('STARTED', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "PlatformRestoreStatus" AS ENUM ('STARTED', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "PlatformDeploymentStatus" AS ENUM ('STARTED', 'COMPLETED', 'FAILED', 'ROLLBACK_STARTED', 'ROLLED_BACK');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'PLATFORM_MAINTENANCE_ENABLED';
ALTER TYPE "AuditAction" ADD VALUE 'PLATFORM_MAINTENANCE_DISABLED';
ALTER TYPE "AuditAction" ADD VALUE 'SCAN_KILL_SWITCH_ENABLED';
ALTER TYPE "AuditAction" ADD VALUE 'SCAN_KILL_SWITCH_DISABLED';
ALTER TYPE "AuditAction" ADD VALUE 'BACKUP_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'BACKUP_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'BACKUP_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'RESTORE_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'RESTORE_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'RESTORE_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'QUEUE_JOB_RETRIED';
ALTER TYPE "AuditAction" ADD VALUE 'QUEUE_JOB_CANCELLED';
ALTER TYPE "AuditAction" ADD VALUE 'PRODUCTION_DEPLOYMENT_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'PRODUCTION_DEPLOYMENT_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'PRODUCTION_ROLLBACK_STARTED';

-- CreateTable
CREATE TABLE "PlatformControl" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL DEFAULT 'platform',
    "maintenanceMode" BOOLEAN NOT NULL DEFAULT false,
    "maintenanceMessage" TEXT,
    "killSwitches" JSONB NOT NULL DEFAULT '{}',
    "updatedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PlatformControl_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PlatformBackup" (
    "id" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "status" "PlatformBackupStatus" NOT NULL DEFAULT 'STARTED',
    "sizeBytes" BIGINT,
    "durationMs" INTEGER,
    "reference" TEXT,
    "checksumSha256" TEXT,
    "encrypted" BOOLEAN NOT NULL DEFAULT false,
    "retentionExpiresAt" TIMESTAMP(3),
    "errorSummary" TEXT,
    "createdById" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "PlatformBackup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PlatformRestore" (
    "id" TEXT NOT NULL,
    "backupId" TEXT NOT NULL,
    "status" "PlatformRestoreStatus" NOT NULL DEFAULT 'STARTED',
    "targetDatabase" TEXT NOT NULL,
    "isRestoreTest" BOOLEAN NOT NULL DEFAULT true,
    "validation" JSONB,
    "errorSummary" TEXT,
    "startedById" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "PlatformRestore_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PlatformDeployment" (
    "id" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "commit" TEXT NOT NULL,
    "build" TEXT,
    "migrationVersion" TEXT,
    "environment" TEXT NOT NULL,
    "status" "PlatformDeploymentStatus" NOT NULL DEFAULT 'STARTED',
    "notes" TEXT,
    "deployedById" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "PlatformDeployment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ServiceLevelObjective" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "target" DOUBLE PRECISION NOT NULL,
    "windowDays" INTEGER NOT NULL DEFAULT 30,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ServiceLevelObjective_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PlatformDrExercise" (
    "id" TEXT NOT NULL,
    "scenario" TEXT NOT NULL,
    "measuredRpoSeconds" INTEGER,
    "measuredRtoSeconds" INTEGER,
    "targetRpoSeconds" INTEGER,
    "targetRtoSeconds" INTEGER,
    "issues" TEXT,
    "runById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PlatformDrExercise_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PlatformControl_key_key" ON "PlatformControl"("key");

-- CreateIndex
CREATE INDEX "PlatformBackup_status_startedAt_idx" ON "PlatformBackup"("status", "startedAt");

-- CreateIndex
CREATE INDEX "PlatformBackup_kind_startedAt_idx" ON "PlatformBackup"("kind", "startedAt");

-- CreateIndex
CREATE INDEX "PlatformRestore_backupId_startedAt_idx" ON "PlatformRestore"("backupId", "startedAt");

-- CreateIndex
CREATE INDEX "PlatformRestore_status_startedAt_idx" ON "PlatformRestore"("status", "startedAt");

-- CreateIndex
CREATE INDEX "PlatformDeployment_environment_startedAt_idx" ON "PlatformDeployment"("environment", "startedAt");

-- CreateIndex
CREATE INDEX "PlatformDeployment_status_startedAt_idx" ON "PlatformDeployment"("status", "startedAt");

-- CreateIndex
CREATE UNIQUE INDEX "ServiceLevelObjective_name_key" ON "ServiceLevelObjective"("name");

-- CreateIndex
CREATE INDEX "PlatformDrExercise_createdAt_idx" ON "PlatformDrExercise"("createdAt");

-- AddForeignKey
ALTER TABLE "PlatformRestore" ADD CONSTRAINT "PlatformRestore_backupId_fkey" FOREIGN KEY ("backupId") REFERENCES "PlatformBackup"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

