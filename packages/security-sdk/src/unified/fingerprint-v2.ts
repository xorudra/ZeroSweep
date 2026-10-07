import { createHash } from "node:crypto";

/**
 * FindingFingerprintServiceV2 (Prompt 20 §12/§13).
 *
 * Fingerprint inputs DEPEND ON FINDING TYPE — a web finding is the same
 * issue when the same check fires on the same endpoint+parameter; a
 * dependency finding is the same issue when the same CVE affects the
 * same package in the same component; a wireless finding is the same
 * issue on the same BSSID with the same rule. V2 keeps the Phase 7
 * canonical identity for web-class findings (existing rows stay
 * comparable) and derives type-appropriate keys for the other domains.
 *
 * Exact deduplication (§13) is the ONLY automatic merge: observations
 * whose V2 fingerprint is identical belong to ONE canonical finding.
 * Similarity below exactness is correlation (§14), never a merge.
 */

export interface FingerprintV2Input {
  workspaceId: string;
  sourceDomain?: string | null;
  category?: string | null;
  // web / api / network identity
  host?: string | null;
  port?: number | null;
  endpoint?: string | null;
  parameter?: string | null;
  // intelligence identity
  cve?: string | null;
  cwe?: string | null;
  ruleId?: string | null;
  // code / dependency identity
  componentPurl?: string | null;
  repositoryId?: string | null;
  filePath?: string | null;
  functionName?: string | null;
  // cloud / kubernetes / container identity
  providerResourceId?: string | null;
  cloudResourceId?: string | null;
  imageDigest?: string | null;
  clusterRef?: string | null;
  namespace?: string | null;
  resourceKind?: string | null;
  resourceName?: string | null;
  // identity / mobile / binary / wireless identity
  directoryObjectId?: string | null;
  mobileApplicationId?: string | null;
  binaryArtifactHash?: string | null;
  wirelessBssid?: string | null;
  wirelessEnvironmentId?: string | null;
}

function norm(v: string | null | undefined): string {
  return (v ?? "").trim().toLowerCase();
}

function normEndpoint(endpoint: string | null | undefined): string {
  if (!endpoint) return "";
  try {
    const u = new URL(endpoint);
    return `${u.protocol}//${u.host.toLowerCase()}${u.pathname.replace(/\/+$/, "")}`;
  } catch {
    return endpoint.trim().toLowerCase().replace(/\/+$/, "");
  }
}

/**
 * Derive the V2 fingerprint. The domain prefix keeps a web issue and a
 * container issue with the same CVE from collapsing into one canonical
 * finding — they are the same VULNERABILITY INTELLIGENCE (§16) but
 * different findings with independent remediation state.
 */
export function fingerprintV2(input: FingerprintV2Input): string {
  const domain = norm(input.sourceDomain) || "unknown";
  const parts: string[] = [norm(input.workspaceId), domain];
  const cve = (input.cve ?? "").trim().toUpperCase();
  const cwe = (input.cwe ?? "").trim().toUpperCase();

  switch (domain) {
    case "sca":
      parts.push(norm(input.componentPurl), cve || norm(input.ruleId));
      break;
    case "container":
    case "kubernetes":
      // package:vuln inside one image digest / workload identity
      parts.push(norm(input.imageDigest) || `${norm(input.clusterRef)}/${norm(input.namespace)}/${norm(input.resourceKind)}/${norm(input.resourceName)}`, norm(input.componentPurl), cve || norm(input.ruleId));
      break;
    case "sast":
    case "secret":
      parts.push(norm(input.repositoryId), norm(input.filePath), norm(input.functionName), norm(input.ruleId) || cwe);
      break;
    case "cloud":
      parts.push(norm(input.providerResourceId) || norm(input.cloudResourceId), norm(input.ruleId), norm(input.category));
      break;
    case "identity":
      parts.push(norm(input.directoryObjectId), norm(input.ruleId), norm(input.category));
      break;
    case "mobile":
      parts.push(norm(input.mobileApplicationId), norm(input.ruleId) || cwe, norm(input.functionName));
      break;
    case "binary":
      parts.push(norm(input.binaryArtifactHash), norm(input.functionName), norm(input.ruleId) || cwe);
      break;
    case "wireless":
      parts.push(norm(input.wirelessEnvironmentId), norm(input.wirelessBssid), norm(input.ruleId), norm(input.category));
      break;
    default:
      // web / api / network / recon / manual / external_import: the
      // Phase 7 identity — host (+port when no URL), endpoint,
      // parameter, rule/CVE/CWE.
      parts.push(
        norm(input.host),
        input.endpoint ? "" : input.port !== undefined && input.port !== null ? String(input.port) : "",
        normEndpoint(input.endpoint),
        norm(input.parameter),
        norm(input.ruleId) || cve || cwe,
      );
  }
  return createHash("sha256").update(parts.join("|")).digest("hex");
}

/** Exact-match verdict (§13): identical V2 fingerprints = same issue. */
export function isExactDuplicate(a: FingerprintV2Input, b: FingerprintV2Input): boolean {
  return fingerprintV2(a) === fingerprintV2(b);
}

export const FindingFingerprintServiceV2 = {
  fingerprint: fingerprintV2,
  isExactDuplicate,
};
