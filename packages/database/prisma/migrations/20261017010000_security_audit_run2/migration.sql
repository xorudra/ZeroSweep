-- Security audit 2026-10-16 (run-2 remediation), additive only:
-- TargetVerification.requestedBy — who opened the verification, so a
-- MANUAL_APPROVAL completion can be required to be independent of both
-- the target's creator and the verification requester
-- (generic-scan-start-self-verified-self-approved).

ALTER TABLE "TargetVerification" ADD COLUMN "requestedBy" TEXT;
