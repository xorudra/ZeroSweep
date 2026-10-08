import { hashContent } from "./evidence";

/**
 * Audit evidence package integrity (Prompt 26 §71–§73, §132/§133).
 * A package is a manifest over file entries: every entry carries the
 * SHA-256 of its (redacted) content; verification recomputes each
 * hash, so any tampering with packaged evidence fails verification.
 */

export interface PackageFileEntry {
  path: string;
  sha256: string;
  sourceRef: string;
  classification: string;
}

export interface AuditPackageManifest {
  packageId: string;
  assessmentId: string;
  frameworkKey: string;
  frameworkVersion: string;
  generatedAt: string;
  classification: "CONFIDENTIAL";
  files: PackageFileEntry[];
  /** Hash over the canonical manifest body (files + identity fields). */
  manifestHash: string;
}

function manifestBody(m: Omit<AuditPackageManifest, "manifestHash">): string {
  const files = [...m.files].sort((a, b) => (a.path < b.path ? -1 : 1))
    .map((f) => `${f.path}|${f.sha256}|${f.sourceRef}|${f.classification}`).join("\n");
  return [m.packageId, m.assessmentId, m.frameworkKey, m.frameworkVersion, m.generatedAt, m.classification, files].join("\n");
}

export function buildPackageManifest(input: {
  packageId: string;
  assessmentId: string;
  frameworkKey: string;
  frameworkVersion: string;
  generatedAt: string;
  files: Array<{ path: string; content: string; sourceRef: string; classification: string }>;
}): AuditPackageManifest {
  const files: PackageFileEntry[] = input.files.map((f) => ({
    path: f.path, sha256: hashContent(f.content), sourceRef: f.sourceRef, classification: f.classification,
  }));
  const base = {
    packageId: input.packageId, assessmentId: input.assessmentId, frameworkKey: input.frameworkKey,
    frameworkVersion: input.frameworkVersion, generatedAt: input.generatedAt,
    classification: "CONFIDENTIAL" as const, files,
  };
  return { ...base, manifestHash: hashContent(manifestBody(base)) };
}

export interface PackageVerification {
  valid: boolean;
  failures: string[];
}

export function verifyPackage(
  manifest: AuditPackageManifest,
  contents: Map<string, string>,
): PackageVerification {
  const failures: string[] = [];
  const { manifestHash, ...rest } = manifest;
  if (hashContent(manifestBody(rest as Omit<AuditPackageManifest, "manifestHash">)) !== manifestHash) {
    failures.push("manifest hash mismatch: the manifest itself was altered");
  }
  for (const file of manifest.files) {
    const content = contents.get(file.path);
    if (content === undefined) { failures.push(`missing packaged file ${file.path}`); continue; }
    if (hashContent(content) !== file.sha256) {
      failures.push(`integrity failure: ${file.path} content hash does not match the manifest (§133)`);
    }
  }
  return { valid: failures.length === 0, failures };
}
