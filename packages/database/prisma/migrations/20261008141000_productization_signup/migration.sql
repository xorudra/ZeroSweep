-- AlterTable
ALTER TABLE "User" ADD COLUMN     "emailVerifiedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "AbuseSignalRecord" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "signal" TEXT NOT NULL,
    "context" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AbuseSignalRecord_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AbuseSignalRecord_organizationId_signal_createdAt_idx" ON "AbuseSignalRecord"("organizationId", "signal", "createdAt");

