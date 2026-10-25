/**
 * Prompt 17 — OWASP Mobile Top 10 + MASVS mappings (§46–§48) and
 * finding fingerprints (§50–§52).
 *
 * The mapping table is VERSIONED (OWASP Mobile Top 10 2024 / MASVS
 * v2). Mappings are applied only where reliable (§47); the platform
 * NEVER claims formal MASVS certification or verification (§48) —
 * control assessments are evidence statements, not certifications.
 */
import { createHash } from "node:crypto";

export const OWASP_MOBILE_TAXONOMY_VERSION = "OWASP Mobile Top 10 2024 / MASVS v2.1";

/** OWASP Mobile Top 10 (2024) categories. */
export const OWASP_MOBILE_TOP10: Record<string, string> = {
  M1: "Improper Credential Usage",
  M2: "Inadequate Supply Chain Security",
  M3: "Insecure Authentication/Authorization",
  M4: "Insufficient Input/Output Validation",
  M5: "Insecure Communication",
  M6: "Inadequate Privacy Controls",
  M7: "Insufficient Binary Protections",
  M8: "Security Misconfiguration",
  M9: "Insecure Data Storage",
  M10: "Insufficient Cryptography",
};

/** Rule → taxonomy mapping. Only rules with a RELIABLE mapping carry
 *  one (§47); unmapped rules stay unmapped rather than guessing. */
export const MOBILE_RULE_TAXONOMY: Record<string, { owaspMobile: string; masvsControl?: string; mastgRef?: string; cwe?: string }> = {
  MOBILE_CLEARTEXT_ENABLED: { owaspMobile: "M5", masvsControl: "MASVS-NETWORK-1", mastgRef: "MASTG-TEST-0019", cwe: "CWE-319" },
  MOBILE_CLEARTEXT_DOMAIN_EXCEPTION: { owaspMobile: "M5", masvsControl: "MASVS-NETWORK-1", cwe: "CWE-319" },
  MOBILE_ATS_ARBITRARY_LOADS: { owaspMobile: "M5", masvsControl: "MASVS-NETWORK-1", cwe: "CWE-319" },
  MOBILE_ATS_DOMAIN_EXCEPTION: { owaspMobile: "M5", masvsControl: "MASVS-NETWORK-1", cwe: "CWE-319" },
  MOBILE_DEBUGGABLE_BUILD: { owaspMobile: "M8", masvsControl: "MASVS-CODE-1", cwe: "CWE-489" },
  MOBILE_BACKUP_ALLOWED: { owaspMobile: "M9", masvsControl: "MASVS-STORAGE-2", cwe: "CWE-922" },
  MOBILE_EXPORTED_COMPONENT_UNPROTECTED: { owaspMobile: "M8", masvsControl: "MASVS-PLATFORM-1", cwe: "CWE-926" },
  MOBILE_HARDCODED_SECRET: { owaspMobile: "M1", masvsControl: "MASVS-CRYPTO-1", mastgRef: "MASTG-TEST-0013", cwe: "CWE-798" },
  MOBILE_WEAK_CRYPTOGRAPHY: { owaspMobile: "M10", masvsControl: "MASVS-CRYPTO-1", cwe: "CWE-327" },
  MOBILE_INSECURE_RANDOM: { owaspMobile: "M10", masvsControl: "MASVS-CRYPTO-2", cwe: "CWE-338" },
  MOBILE_WORLD_READABLE_STORAGE: { owaspMobile: "M9", masvsControl: "MASVS-STORAGE-1", cwe: "CWE-276" },
  MOBILE_SENSITIVE_DATA_LOGGING: { owaspMobile: "M9", masvsControl: "MASVS-STORAGE-2", cwe: "CWE-532" },
  MOBILE_WEBVIEW_FILE_ACCESS: { owaspMobile: "M8", masvsControl: "MASVS-PLATFORM-2", cwe: "CWE-749" },
  MOBILE_WEBVIEW_JS_BRIDGE: { owaspMobile: "M8", masvsControl: "MASVS-PLATFORM-2", cwe: "CWE-749" },
  MOBILE_DEBUG_SIGNING: { owaspMobile: "M8", masvsControl: "MASVS-CODE-1", cwe: "CWE-321" },
  MOBILE_WEAK_SIGNING_ALGORITHM: { owaspMobile: "M7", masvsControl: "MASVS-RESILIENCE-1", cwe: "CWE-327" },
  MOBILE_BINARY_NO_PIE: { owaspMobile: "M7", masvsControl: "MASVS-RESILIENCE-3", cwe: "CWE-732" },
  MOBILE_BINARY_NO_NX: { owaspMobile: "M7", masvsControl: "MASVS-RESILIENCE-3", cwe: "CWE-732" },
  MOBILE_BINARY_NO_CANARY: { owaspMobile: "M7", masvsControl: "MASVS-RESILIENCE-3", cwe: "CWE-732" },
  MOBILE_BINARY_NO_RELRO: { owaspMobile: "M7", masvsControl: "MASVS-RESILIENCE-3", cwe: "CWE-732" },
  MOBILE_BINARY_DEBUG_SYMBOLS: { owaspMobile: "M7", masvsControl: "MASVS-RESILIENCE-2", cwe: "CWE-200" },
  MOBILE_PINNING_ABSENT_OBSERVED_CLEARTEXT: { owaspMobile: "M5", masvsControl: "MASVS-NETWORK-2", cwe: "CWE-295" },
  MOBILE_RUNTIME_CLEARTEXT_TRAFFIC: { owaspMobile: "M5", masvsControl: "MASVS-NETWORK-1", cwe: "CWE-319" },
  MOBILE_DEPENDENCY_VULNERABILITY: { owaspMobile: "M2", masvsControl: "MASVS-CODE-2", cwe: "CWE-1035" },
};

/** The verbatim posture statement (§48): assessments reference MASVS
 *  controls; they are NOT a MASVS certification or verification. */
export const MASVS_NO_CERTIFICATION_DISCLAIMER =
  "Control assessments reference OWASP MASVS controls for traceability only. They are not a formal MASVS verification or certification, and no certification claim is made (§48).";

/**
 * §50/§51: mobile finding fingerprints.
 *  - `mobileFindingFingerprint` is the per-build canonical identity:
 *    application + build hash + platform + file/component + rule +
 *    CWE + finding class.
 *  - `mobileCrossBuildKey` is the CROSS-BUILD identity: identical
 *    except the build hash is replaced by the application identity,
 *    so the same root issue in v1.2 and v1.3 correlates while the
 *    build-specific observations are preserved separately.
 */
export function mobileFindingFingerprint(parts: {
  applicationRef: string;
  buildHash: string;
  platform: string;
  component: string;
  ruleId: string;
  cwe?: string;
  findingType: string;
}): string {
  const basis = [
    "mobile", parts.applicationRef.toLowerCase(), parts.buildHash.toLowerCase(),
    parts.platform.toUpperCase(), parts.component.toLowerCase(), parts.ruleId.toUpperCase(),
    (parts.cwe ?? "").toUpperCase(), parts.findingType.toUpperCase(),
  ].join("|");
  return createHash("sha256").update(`zerosweep-mobile-v1\0${basis}`).digest("hex");
}

export function mobileCrossBuildKey(parts: {
  applicationRef: string;
  platform: string;
  component: string;
  ruleId: string;
  cwe?: string;
  findingType: string;
}): string {
  const basis = [
    "mobile-xbuild", parts.applicationRef.toLowerCase(),
    parts.platform.toUpperCase(), parts.component.toLowerCase(), parts.ruleId.toUpperCase(),
    (parts.cwe ?? "").toUpperCase(), parts.findingType.toUpperCase(),
  ].join("|");
  return createHash("sha256").update(`zerosweep-mobile-v1\0${basis}`).digest("hex");
}
