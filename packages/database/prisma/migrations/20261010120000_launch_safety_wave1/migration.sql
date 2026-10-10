-- Launch Safety Standard wave 1 (owner-ordered 2026-10-10).
-- F26: persist the registration consent record (Terms/Privacy version
-- accepted + when) on the user row. Nullable: accounts created before
-- consent capture keep NULL — never backfilled with a guess.
-- F28/F29: audit actions for self-service account deletion and
-- personal-data export.

-- AlterTable
ALTER TABLE "User" ADD COLUMN "termsAcceptedAt" TIMESTAMP(3);
ALTER TABLE "User" ADD COLUMN "termsVersion" TEXT;

-- AlterEnum
ALTER TYPE "AuditAction" ADD VALUE 'USER_ACCOUNT_DELETED';
ALTER TYPE "AuditAction" ADD VALUE 'USER_DATA_EXPORTED';
