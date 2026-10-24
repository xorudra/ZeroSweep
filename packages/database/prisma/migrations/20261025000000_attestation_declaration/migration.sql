-- Attestation declaration record (2026-10-25, owner order): guidelines
-- shown before the "I have permission" tick, and the declaration's
-- network address stored with the verification row. Additive only.
ALTER TABLE "TargetVerification" ADD COLUMN "attestationIp" TEXT;
ALTER TABLE "TargetVerification" ADD COLUMN "attestationGuidelinesVersion" TEXT;
ALTER TABLE "TargetVerification" ADD COLUMN "attestationAt" TIMESTAMP(3);
