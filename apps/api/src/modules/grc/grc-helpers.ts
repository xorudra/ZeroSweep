import { redactEvidenceText } from "@zerosweep/security-sdk";

export { buildPackageManifest, verifyPackage, hashEvidence, GRC_DISCLAIMER } from "@zerosweep/security-sdk";

/**
 * §73 + Prompt 20 redaction discipline: every string that enters an
 * audit package or a GRC report passes the platform evidence redactor
 * first, so planted secrets in snapshots/notes can never ride along
 * into an issued artifact.
 */
export function redactForPackage(text: string): string {
  return redactEvidenceText(text);
}
