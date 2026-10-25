-- Add TARGET_DELETED to the audit action enum (the targets soft-delete
-- records it; without this value the audit write fails and the delete
-- endpoint returns 500 after the row was already soft-deleted).
ALTER TYPE "AuditAction" ADD VALUE 'TARGET_DELETED';
