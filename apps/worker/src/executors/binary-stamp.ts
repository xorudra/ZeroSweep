/**
 * Prompt 18 §50–§58: canonical binary finding identity, shared by the
 * worker stores. Processed findings from binary adapters or the
 * platform analysis receive their identity here — artifact (id +
 * SHA-256), §56 finding type, §62 reachability default and the §57
 * cross-build fingerprint (lineage + component + rule + CWE + class;
 * absolute addresses are excluded by construction). The stamped
 * fingerprint becomes the correlation key, so checksec + Ghidra
 * hardening reports and Ghidra + radare2 function reports converge
 * on ONE canonical finding with every observation preserved (§58).
 *
 * Dependency findings (componentPurl + CVE) keep the dependency
 * correlation identity (PURL + CVE) — they receive the binary
 * identity fields but NOT a fingerprint rewrite.
 */
import {
  BINARY_SLUGS, binaryFindingFingerprint, type BinaryFindingType,
} from "@zerosweep/security-sdk";
import type { ProcessedFinding } from "./result-processor";

export interface BinaryScanIdentity {
  artifactId: string;
  artifactHash: string;
  artifactName: string;
  format: string;
  architecture?: string;
  environment?: string;
}

export function isBinaryProcessedFinding(f: ProcessedFinding): boolean {
  return f.binaryFindingType !== undefined
    || (BINARY_SLUGS as readonly string[]).includes(f.sourceTool)
    || (f.ruleId?.startsWith("BINARY_") ?? false);
}

function defaultFindingType(f: ProcessedFinding): BinaryFindingType {
  if (f.binaryFindingType) return f.binaryFindingType as BinaryFindingType;
  if (f.ruleId === "BINARY_EMBEDDED_SECRET" || f.secret) return "BINARY_SECRET";
  if (f.componentPurl && f.cve) return "BINARY_DEPENDENCY_VULNERABILITY";
  if ((f.ruleId ?? "").includes("HARDENING") || /^(BINARY_NO_|BINARY_PARTIAL_)/.test(f.ruleId ?? "")) return "BINARY_HARDENING_FINDING";
  if ((f.ruleId ?? "").startsWith("BINARY_")) return "BINARY_STATIC_CODE_FINDING";
  return "BINARY_CONFIGURATION_FINDING";
}

export function stampBinaryFindings(findings: ProcessedFinding[], identity: BinaryScanIdentity): ProcessedFinding[] {
  const lineage = `${identity.format}:${identity.architecture ?? "unknown"}:${identity.artifactName}`;
  return findings.map((f) => {
    if (!isBinaryProcessedFinding(f)) return f;
    const findingType = defaultFindingType(f);
    const stamped: ProcessedFinding = {
      ...f,
      binaryArtifactId: identity.artifactId,
      binaryArtifactHash: identity.artifactHash,
      binaryFindingType: findingType,
      ...(f.binaryReachability ? {} : { binaryReachability: "UNKNOWN" }),
    };
    if (stamped.componentPurl && stamped.cve) return stamped; // dependency identity preserved
    const fingerprint = binaryFindingFingerprint({
      lineage,
      component: stamped.binaryComponent ?? stamped.filePath ?? "artifact",
      ruleId: stamped.ruleId ?? "BINARY",
      ...(stamped.cwe ? { cwe: stamped.cwe } : {}),
      findingClass: findingType,
      location: stamped.binaryComponent ?? stamped.filePath ?? "artifact",
    });
    stamped.binaryFingerprint = fingerprint;
    stamped.fingerprint = fingerprint;
    return stamped;
  });
}
