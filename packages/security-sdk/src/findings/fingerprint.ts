import { createHash } from "node:crypto";

/** Deterministic fingerprint used later for deduplication/correlation. */
export function findingFingerprint(parts: {
  toolFamily: string;
  asset: string;
  endpoint?: string;
  parameter?: string;
  vulnClass: string;
  cve?: string;
  cwe?: string;
}): string {
  const basis = [
    parts.toolFamily.toLowerCase(),
    parts.asset.toLowerCase(),
    (parts.endpoint ?? "").toLowerCase(),
    (parts.parameter ?? "").toLowerCase(),
    parts.vulnClass.toLowerCase(),
    (parts.cve ?? parts.cwe ?? "").toUpperCase(),
  ].join("|");
  return createHash("sha256").update(basis).digest("hex");
}
