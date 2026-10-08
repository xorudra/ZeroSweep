-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'FINDING_COMMENT_ADDED';
ALTER TYPE "AuditAction" ADD VALUE 'EVIDENCE_VISIBILITY_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'FINDING_TEMPLATE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'REPORT_TEMPLATE_VERSION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'REPORT_ARCHIVED';

