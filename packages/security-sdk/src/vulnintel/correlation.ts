import { parseCpe, formatCpe } from "../vulnmgmt/normalize";
import { parsePurl, formatPurl, productKey } from "./identity";
import { evaluateRanges } from "./versions";
import type { AffectedRangeData, ComponentMatchResult } from "./types";

/**
 * SBOM component ↔ vulnerability correlation (Prompt 30 §51–§58).
 *
 * Pipeline (§51): CVE → affected product/range → normalized component →
 * SBOM component → repository/image/asset/workload.
 *
 * NO FUZZY CERTAINTY (§52): name similarity alone can only ever produce
 * HEURISTIC / POTENTIALLY_AFFECTED. A component is AFFECTED only via an
 * exact identifier (PURL/CPE/package) plus a version-range verdict, or
 * via a scanner's own confirmed observation (§57).
 */

export interface CorrelatableComponent {
  id: string;
  name: string;
  version?: string;
  ecosystem: string;
  purl: string;
  cpe?: string;
}

export interface ScannerObservation {
  scanner: string;
  affected: boolean;
  detail?: string;
}

export function correlateComponentToCve(input: {
  component: CorrelatableComponent;
  cveId: string;
  ranges: AffectedRangeData[];
  affectedProducts: { vendor: string; product: string; identifier?: string; identifierType?: string }[];
  scannerObservations?: ScannerObservation[];
}): ComponentMatchResult {
  const { component, ranges } = input;
  const evidence: string[] = [];
  const compPurl = parsePurl(component.purl);
  const compPurlStr = compPurl ? formatPurl(compPurl) : undefined;
  const compCpeParts = parseCpe(component.cpe);
  const compCpeStr = compCpeParts ? formatCpe(compCpeParts) : undefined;

  // --- Scanner observations (§57/§58): preserved verbatim. A single
  // agreeing scanner confirms; DISAGREEMENT never silently resolves —
  // it downgrades to POTENTIALLY_AFFECTED with both observations shown.
  const observations = input.scannerObservations ?? [];
  const scannersAffected = observations.filter((o) => o.affected);
  const scannersNotAffected = observations.filter((o) => !o.affected);
  if (scannersAffected.length && scannersNotAffected.length) {
    evidence.push(`scanner disagreement (§58): ${scannersAffected.map((o) => o.scanner).join(", ")} report affected; ${scannersNotAffected.map((o) => o.scanner).join(", ")} report not affected — both observations preserved, no silent selection`);
    return { matchType: "SCANNER_CONFIRMED", confidence: "AMBIGUOUS", affectedStatus: "POTENTIALLY_AFFECTED", evidence };
  }
  if (scannersAffected.length && !scannersNotAffected.length) {
    evidence.push(`scanner-confirmed by ${scannersAffected.map((o) => o.scanner).join(", ")} with no dissenting observation`);
    return { matchType: "SCANNER_CONFIRMED", confidence: "HIGH", affectedStatus: "AFFECTED", evidence };
  }

  // --- Exact identifier matches (§55)
  let identifierMatched = false;
  let identifierType: "PURL_EXACT" | "CPE_EXACT" | "PACKAGE_EXACT" | undefined;
  for (const ap of input.affectedProducts) {
    if (ap.identifier && ap.identifierType === "PURL") {
      const apPurl = parsePurl(ap.identifier);
      if (apPurl && compPurlStr && formatPurl({ ...apPurl, version: undefined }) === formatPurl({ ...compPurl!, version: undefined })) {
        identifierMatched = true; identifierType = "PURL_EXACT";
        evidence.push(`PURL identity matches affected product ${ap.identifier} (§55)`);
        break;
      }
    }
    if (ap.identifier && ap.identifierType === "CPE" && compCpeStr) {
      const apCpe = parseCpe(ap.identifier);
      if (apCpe && apCpe.vendor === compCpeParts?.vendor && apCpe.product === compCpeParts?.product) {
        identifierMatched = true; identifierType = "CPE_EXACT";
        evidence.push(`CPE vendor/product matches affected product ${ap.identifier} (§55)`);
        break;
      }
    }
    if (!ap.identifier && ap.product.toLowerCase() === component.name.toLowerCase()
      && (component.ecosystem || ap.vendor) && ranges.some((r) => r.vendor.toLowerCase() === ap.vendor.toLowerCase() && r.product.toLowerCase() === ap.product.toLowerCase())) {
      identifierMatched = true; identifierType = "PACKAGE_EXACT";
      evidence.push(`package identity ${productKey(ap.vendor, ap.product)} matches component in ecosystem ${component.ecosystem}`);
      break;
    }
  }

  // Ranges that belong to this component's product.
  const productRanges = ranges.filter((r) => {
    if (compPurl && r.ecosystem && r.ecosystem.toLowerCase() === compPurl.type && r.product.toLowerCase() === compPurl.name.toLowerCase()) return true;
    if (compCpeParts && r.product.toLowerCase() === compCpeParts.product.toLowerCase() && r.vendor.toLowerCase() === compCpeParts.vendor.toLowerCase()) return true;
    return r.product.toLowerCase() === component.name.toLowerCase();
  });

  if (identifierMatched) {
    if (!component.version) {
      evidence.push("component version unknown — range cannot be evaluated (§52)");
      return { matchType: identifierType!, confidence: "MEDIUM", affectedStatus: "UNKNOWN", evidence };
    }
    if (!productRanges.length) {
      evidence.push("identifier matched but the source published no machine-checkable version range — potential only (§52)");
      return { matchType: identifierType!, confidence: "MEDIUM", affectedStatus: "POTENTIALLY_AFFECTED", evidence };
    }
    const evaluation = evaluateRanges(component.version, productRanges);
    evidence.push(...evaluation.reasons);
    if (evaluation.verdict === "AFFECTED") {
      return { matchType: "VERSION_RANGE", confidence: "HIGH", affectedStatus: "AFFECTED", evidence };
    }
    if (evaluation.verdict === "NOT_AFFECTED") {
      return { matchType: "VERSION_RANGE", confidence: "HIGH", affectedStatus: "NOT_AFFECTED", evidence };
    }
    return { matchType: identifierType!, confidence: "MEDIUM", affectedStatus: "UNKNOWN", evidence };
  }

  // --- Heuristic: bare product-name similarity (§56). NEVER confirmed.
  const nameSimilar = input.affectedProducts.some((ap) => {
    const a = ap.product.toLowerCase();
    const b = component.name.toLowerCase();
    return a === b || a.includes(b) || b.includes(a);
  }) || productRanges.length > 0;
  if (nameSimilar) {
    evidence.push("only product-name similarity exists — heuristic match stays POTENTIALLY_AFFECTED until corroborated (§56)");
    return { matchType: "HEURISTIC", confidence: "LOW", affectedStatus: "POTENTIALLY_AFFECTED", evidence };
  }

  return { matchType: "HEURISTIC", confidence: "LOW", affectedStatus: "UNKNOWN", evidence: ["no identifier, range, or name relationship to this CVE's affected products"] };
}

// ------------------------------ reachability (§76/§77) ------------------------------

export type ReachabilityStatus = "UNKNOWN" | "POTENTIALLY_REACHABLE" | "REACHABLE" | "NOT_REACHABLE";

export interface ReachabilityInput {
  /** Static analysis produced an actual call path to the vulnerable code. */
  callPathEvidence?: boolean;
  /** Component is a direct dependency of shipped code. */
  directDependency?: boolean;
  /** Analysis ran but could not determine reachability. */
  analysisIncomplete?: boolean;
  /** Positive evidence the vulnerable code path is dead / component unused at runtime. */
  positiveUnreachableEvidence?: boolean;
}

/**
 * §77 is a hard rule: NOT_REACHABLE requires POSITIVE evidence. A static
 * analysis that merely failed to find a path yields UNKNOWN (or
 * POTENTIALLY_REACHABLE for direct dependencies) — never NOT_REACHABLE.
 */
export function assessReachability(input: ReachabilityInput): { status: ReachabilityStatus; confidence: "LOW" | "MEDIUM" | "HIGH"; rationale: string } {
  if (input.callPathEvidence) {
    return { status: "REACHABLE", confidence: "HIGH", rationale: "static analysis produced a call path to the vulnerable code (§76)" };
  }
  if (input.positiveUnreachableEvidence) {
    return { status: "NOT_REACHABLE", confidence: "MEDIUM", rationale: "positive evidence the vulnerable code path cannot execute (§77)" };
  }
  if (input.directDependency) {
    return { status: "POTENTIALLY_REACHABLE", confidence: "MEDIUM", rationale: "direct dependency of shipped code; no call-path evidence either way (§77)" };
  }
  if (input.analysisIncomplete) {
    return { status: "UNKNOWN", confidence: "LOW", rationale: "analysis incomplete — absence of a found path is not evidence of unreachability (§77)" };
  }
  return { status: "UNKNOWN", confidence: "LOW", rationale: "no reachability evidence recorded" };
}
