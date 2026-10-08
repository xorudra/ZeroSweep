/**
 * Prompt 35 §129–§132/§160 — AI Mobile Copilot governance.
 *
 * The copilot may summarize assessments, explain permission /
 * component / hardening risk, compare versions, explain dependency
 * CVEs and draft reports (§129) over governed, redacted records
 * only. It can NEVER (§131/§160): generate malware, create
 * persistence, steal credentials, instrument arbitrary third-party
 * devices/apps, run unrestricted Frida scripts, create weaponized
 * binary exploits, or bypass licensing/DRM. Requests in those
 * classes are refused deterministically BEFORE any provider call.
 */

const REFUSAL_PATTERNS: { re: RegExp; category: string }[] = [
  { re: /\b(generate|create|write|build)\b[^.]{0,60}\b(exploit|shellcode|rop chain|payload)\b/i, category: "WEAPONIZED_EXPLOIT" },
  { re: /\b(working|weaponized)\b[^.]{0,30}\b(exploit|payload)\b/i, category: "WEAPONIZED_EXPLOIT" },
  { re: /\b(persistent|persistence)\b[^.]{0,30}\b(payload|implant|backdoor)\b/i, category: "PERSISTENCE" },
  { re: /\b(malware|ransomware|spyware|trojan|keylogger)\b/i, category: "MALWARE" },
  { re: /\b(steal|extract|dump|harvest)\b[^.]{0,40}\b(credentials|passwords|tokens|keychain)\b/i, category: "CREDENTIAL_THEFT" },
  { re: /\b(bypass|remove|disable)\b[^.]{0,40}\b(drm|licen[cs]e|activation)\b/i, category: "DRM_LICENSE_BYPASS" },
  { re: /\binstrument\b[^.]{0,40}\b(any|arbitrary|third-party)\b/i, category: "ARBITRARY_INSTRUMENTATION" },
  { re: /\b(unrestricted|arbitrary)\b[^.]{0,20}\bfrida\b/i, category: "UNRESTRICTED_FRIDA" },
];

export interface MobbinAiGuardResult {
  allowed: boolean;
  category: string | null;
  refusal: string | null;
}

/** §131/§160: deterministic refusal for prohibited request classes.
 *  The refusal is the whole answer — nothing is executed, no
 *  provider is called with the request. */
export function guardMobileAiRequest(prompt: string): MobbinAiGuardResult {
  for (const p of REFUSAL_PATTERNS) {
    if (p.re.test(prompt)) {
      return {
        allowed: false,
        category: p.category,
        refusal: `Refused (${p.category}): the AI Mobile Copilot is defensive-only — it explains findings, risk and remediation for authorized applications and never generates exploits, payloads, persistence, credential theft or license/DRM bypasses (§131).`,
      };
    }
  }
  return { allowed: true, category: null, refusal: null };
}

// ── §132 deterministic NL → typed query plans ─────────────────────

export type MobbinNlQueryKind =
  | "CRITICAL_IN_LATEST_BUILD"
  | "APPS_WITH_VULNERABLE_NATIVE_LIBRARIES"
  | "SECRETS_IN_PRODUCTION_BUILDS"
  | "PERSISTED_ACROSS_VERSIONS"
  | "CLEARTEXT_TRAFFIC_APPS"
  | "UNSUPPORTED";

export interface MobbinNlPlan {
  kind: MobbinNlQueryKind;
  domainIn: ("MOBILE" | "BINARY")[];
  severityIn?: string[];
  filters: Record<string, string | boolean>;
  executed: false;
}

export function planMobileNlQuery(text: string): MobbinNlPlan {
  const t = text.toLowerCase();
  const base: MobbinNlPlan = { kind: "UNSUPPORTED", domainIn: ["MOBILE"], filters: {}, executed: false };
  if (/critical/.test(t) && /(latest|newest|current)/.test(t) && /(build|android|app)/.test(t)) {
    return { ...base, kind: "CRITICAL_IN_LATEST_BUILD", severityIn: ["CRITICAL"], filters: { latestBuildOnly: true } };
  }
  if (/vulnerable/.test(t) && /native librar/.test(t)) {
    return { ...base, kind: "APPS_WITH_VULNERABLE_NATIVE_LIBRARIES", domainIn: ["MOBILE", "BINARY"], filters: { nativeLibraryVulnerable: true } };
  }
  if (/secret/.test(t) && /production/.test(t)) {
    return { ...base, kind: "SECRETS_IN_PRODUCTION_BUILDS", filters: { secretFindings: true, environment: "PRODUCTION" } };
  }
  if (/persist/.test(t) && /version/.test(t)) {
    return { ...base, kind: "PERSISTED_ACROSS_VERSIONS", filters: { carryForward: "PERSISTING" } };
  }
  if (/cleartext/.test(t)) {
    return { ...base, kind: "CLEARTEXT_TRAFFIC_APPS", filters: { cleartextTraffic: true } };
  }
  return base;
}
