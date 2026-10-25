/**
 * Governed rule policies (Prompt 12 §22, §30, §101). Semgrep packs and
 * CodeQL suites come ONLY from the platform catalog below: pinned,
 * administrator-approved, versioned. Users can REQUEST packs by id —
 * anything outside the catalog (arbitrary rule paths, uploaded rules,
 * ad-hoc queries) is REJECTED, mirroring the Nuclei template governance
 * of Prompt 7. Custom organization rules enter only as approved catalog
 * entries, never as scan-time input.
 */

export interface SemgrepRulePack {
  id: string;
  name: string;
  /** Policy pin — the catalog version approved for use. */
  version: string;
  languages: string[]; // empty = language-agnostic
  profiles: string[];
  approvalState: "APPROVED";
}

/** The governed Semgrep pack catalog (§22). Registry pack ids are the
 *  public Semgrep registry names; the pin records the approved policy
 *  version in ZeroSweep, and pack content is fetched by the tool itself
 *  on source workers — never supplied by users. */
export const SEMGREP_RULE_PACKS: SemgrepRulePack[] = [
  { id: "p/security-audit", name: "Security Audit", version: "1.0.0", languages: [], profiles: ["SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SAST_ONLY"], approvalState: "APPROVED" },
  { id: "p/owasp-top-ten", name: "OWASP Top Ten", version: "1.0.0", languages: [], profiles: ["SOURCE_COMPREHENSIVE"], approvalState: "APPROVED" },
  { id: "p/python", name: "Python Security", version: "1.0.0", languages: ["Python"], profiles: ["SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SAST_ONLY"], approvalState: "APPROVED" },
  { id: "p/javascript", name: "JavaScript Security", version: "1.0.0", languages: ["JavaScript", "TypeScript"], profiles: ["SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SAST_ONLY"], approvalState: "APPROVED" },
  { id: "p/java", name: "Java Security", version: "1.0.0", languages: ["Java"], profiles: ["SOURCE_COMPREHENSIVE", "SAST_ONLY"], approvalState: "APPROVED" },
  { id: "p/ruby", name: "Ruby Security", version: "1.0.0", languages: ["Ruby"], profiles: ["SOURCE_COMPREHENSIVE", "SAST_ONLY"], approvalState: "APPROVED" },
  { id: "p/golang", name: "Go Security", version: "1.0.0", languages: ["Go"], profiles: ["SOURCE_COMPREHENSIVE", "SAST_ONLY"], approvalState: "APPROVED" },
  { id: "p/secrets", name: "Secrets (defense in depth)", version: "1.0.0", languages: [], profiles: ["SOURCE_COMPREHENSIVE"], approvalState: "APPROVED" },
];

export interface SemgrepSelection {
  packs: string[];
  rejected: { id: string; reason: string }[];
}

/**
 * Resolve the Semgrep configuration for a scan (§22): profile defaults
 * filtered by detected languages; explicit requests are validated
 * against the catalog — unknown or path-like ids are rejected, never
 * passed through to the tool.
 */
export function resolveSemgrepPacks(input: {
  profile: string;
  languages: string[];
  requested?: string[];
}): SemgrepSelection {
  const rejected: SemgrepSelection["rejected"] = [];
  const chosen = new Map<string, SemgrepRulePack>();
  if (input.requested && input.requested.length > 0) {
    for (const id of input.requested) {
      const pack = SEMGREP_RULE_PACKS.find((p) => p.id === id && p.approvalState === "APPROVED");
      if (!pack) {
        rejected.push({ id, reason: "not in the governed Semgrep pack catalog — arbitrary rule content is never accepted (§22)" });
        continue;
      }
      chosen.set(pack.id, pack);
    }
  } else {
    for (const pack of SEMGREP_RULE_PACKS) {
      if (!pack.profiles.includes(input.profile)) continue;
      if (pack.languages.length > 0 && !pack.languages.some((l) => input.languages.includes(l))) continue;
      chosen.set(pack.id, pack);
    }
  }
  return { packs: [...chosen.keys()].sort(), rejected };
}

// ── CodeQL (§28–§30) ──────────────────────────────────────────────────

export interface CodeqlLanguagePlan {
  language: string;
  /** Governed suite id from the catalog (§30). */
  suite: string;
  /** Build mode the safe pipeline may use. */
  buildMode: "none" | "BUILD_REQUIRED";
}

const CODEQL_SUITE_BY_LANGUAGE: Record<string, string> = {
  javascript: "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
  typescript: "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
  python: "codeql/python-queries:codeql-suites/python-security-extended.qls",
  java: "codeql/java-queries:codeql-suites/java-security-extended.qls",
  ruby: "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
  go: "codeql/go-queries:codeql-suites/go-security-extended.qls",
  csharp: "codeql/csharp-queries:codeql-suites/csharp-security-extended.qls",
};

/** Languages CodeQL can extract WITHOUT building the target (§29).
 *  Compiled languages outside this set are BUILD_REQUIRED in safe mode
 *  — the platform never builds target code to satisfy a scanner (§14). */
const BUILD_MODE_NONE_LANGUAGES = new Set(["javascript", "typescript", "python", "java", "ruby", "go", "csharp"]);

const LANGUAGE_ALIASES: Record<string, string> = {
  "JavaScript": "javascript", "TypeScript": "typescript", "Python": "python",
  "Java": "java", "Ruby": "ruby", "Go": "go", "C#": "csharp",
  "C": "cpp", "C++": "cpp", "Swift": "swift", "Kotlin": "java",
};

export interface CodeqlPlan {
  languages: CodeqlLanguagePlan[];
  /** Languages that cannot be analyzed without building the target. */
  buildRequired: string[];
  unsupported: string[];
}

/** Resolve the governed CodeQL plan for the detected languages (§30). */
export function resolveCodeqlPlan(detectedLanguages: string[]): CodeqlPlan {
  const languages: CodeqlLanguagePlan[] = [];
  const buildRequired: string[] = [];
  const unsupported: string[] = [];
  const seen = new Set<string>();
  for (const detected of detectedLanguages) {
    const lang = LANGUAGE_ALIASES[detected] ?? detected.toLowerCase();
    if (seen.has(lang)) continue;
    seen.add(lang);
    const suite = CODEQL_SUITE_BY_LANGUAGE[lang];
    if (!suite) {
      if (["cpp", "swift"].includes(lang)) { buildRequired.push(lang); } else { unsupported.push(lang); }
      continue;
    }
    if (!BUILD_MODE_NONE_LANGUAGES.has(lang)) { buildRequired.push(lang); continue; }
    languages.push({ language: lang, suite, buildMode: "none" });
  }
  return { languages, buildRequired, unsupported };
}
