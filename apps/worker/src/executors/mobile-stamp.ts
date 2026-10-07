/**
 * Prompt 17 §50/§51: canonical mobile finding identity, shared by the
 * worker stores. Processed findings arriving from mobile adapters or
 * platform analysis receive their §50 identity here — application,
 * build (id + SHA-256), platform, finding type, OWASP Mobile / MASVS
 * mappings from the versioned taxonomy — and their canonical
 * fingerprint (application + build hash + platform + file/component +
 * rule + CWE + class) plus the SEPARATE cross-build key (§51, which
 * deliberately excludes the build hash so retest comparison across
 * builds matches the same issue).
 *
 * Dependency findings (componentPurl + CVE) keep the dependency
 * correlation identity (§45: PURL + CVE) — they receive the mobile
 * identity fields but NOT a fingerprint rewrite.
 */
import {
  MOBILE_SLUGS, MOBILE_RULE_TAXONOMY, canonicalMobileFingerprint, crossBuildKeyFor,
  type MobileFindingType,
} from "@dsrclone/security-sdk";
import type { ProcessedFinding } from "./result-processor";

export interface MobileScanIdentity {
  applicationId: string;
  applicationRef: string;
  buildId: string;
  buildHash: string;
  platform: "ANDROID" | "IOS";
  environment?: string;
}

export function isMobileProcessedFinding(f: ProcessedFinding): boolean {
  return f.mobileFindingType !== undefined
    || (MOBILE_SLUGS as readonly string[]).includes(f.sourceTool)
    || (f.ruleId?.startsWith("MOBILE_") ?? false);
}

function defaultFindingType(f: ProcessedFinding): MobileFindingType {
  if (f.mobileFindingType) return f.mobileFindingType as MobileFindingType;
  if (f.secret) return "MOBILE_SECRET";
  if (f.componentPurl && f.cve) return "MOBILE_DEPENDENCY_VULNERABILITY";
  const rule = f.ruleId ?? "";
  if (rule.includes("RUNTIME")) return "MOBILE_RUNTIME_FINDING";
  if (rule.includes("BINARY") || f.sourceTool === "ghidra") return "MOBILE_BINARY_FINDING";
  if (/CLEARTEXT|ATS_|PINNING|TRAFFIC|NETWORK/.test(rule)) return "MOBILE_NETWORK_FINDING";
  if (f.filePath) return "MOBILE_CODE_FINDING";
  return "MOBILE_MISCONFIGURATION";
}

export function stampMobileFindings(findings: ProcessedFinding[], identity: MobileScanIdentity): ProcessedFinding[] {
  return findings.map((f) => {
    if (!isMobileProcessedFinding(f)) return f;
    const findingType = defaultFindingType(f);
    const taxonomy = f.ruleId ? MOBILE_RULE_TAXONOMY[f.ruleId] : undefined;
    const stamped: ProcessedFinding = {
      ...f,
      mobileApplicationId: identity.applicationId,
      mobileBuildId: identity.buildId,
      mobileBuildHash: identity.buildHash,
      mobilePlatform: identity.platform,
      mobileFindingType: findingType,
      ...(taxonomy?.owaspMobile && !f.owaspMobile ? { owaspMobile: taxonomy.owaspMobile } : {}),
      ...(taxonomy?.masvsControl && !f.masvsControl ? { masvsControl: taxonomy.masvsControl } : {}),
      ...(taxonomy?.cwe && !f.cwe ? { cwe: taxonomy.cwe } : {}),
    };
    if (stamped.componentPurl && stamped.cve) return stamped; // §45 identity preserved
    // §50/§51: the SDK canonicalization consumes a normalized-finding
    // projection of the processed record (title/description/severity
    // are not identity inputs — file/component, rule, CWE, class and
    // the secret fingerprint are).
    const projection = {
      title: stamped.title, description: stamped.description,
      severity: stamped.severity as never, confidence: stamped.confidence,
      references: [], sourceTool: stamped.sourceTool, sourceFingerprint: stamped.fingerprint,
      ...(stamped.host ? { host: stamped.host } : {}),
      ...(stamped.endpoint ? { endpoint: stamped.endpoint } : {}),
      ...(stamped.cwe ? { cwe: stamped.cwe } : {}),
      ...(stamped.ruleId ? { ruleId: stamped.ruleId } : {}),
      ...(stamped.filePath ? { filePath: stamped.filePath } : {}),
      ...(stamped.mobileComponent ? { mobileComponent: stamped.mobileComponent } : {}),
      mobileFindingType: findingType as never,
      ...(stamped.secret ? { secret: stamped.secret } : {}),
    } as never;
    const correlationIdentity = { applicationRef: identity.applicationRef, buildHash: identity.buildHash, platform: identity.platform };
    stamped.fingerprint = canonicalMobileFingerprint(projection, correlationIdentity);
    stamped.crossBuildFingerprint = crossBuildKeyFor(projection, correlationIdentity);
    return stamped;
  });
}
