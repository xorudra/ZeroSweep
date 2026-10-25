/**
 * Prompt 17 — decompiled-source pattern analysis (§25/§28/§76–§86).
 *
 * Decompiled source is DATA (§24): it is scanned with bounded,
 * evidence-backed patterns and NEVER executed. Secret scanning reuses
 * the Prompt 12 discipline exactly — platform fingerprinting, an
 * HMAC fingerprint, a redacted preview; the raw value is dropped at
 * scan time and exists in no output (§28/§106).
 */
import { SecretFingerprintService, classifySecretType, redactSecretsInText, redactedPreview } from "../code/secrets";
import type { NormalizedFinding, NormalizedMobileEndpoint } from "../findings/finding.types";
import { sanitizeMobileText } from "./sanitize";

export interface MobileSourceSnippet {
  path: string;
  text: string;
}

export interface MobilePatternObservation {
  ruleId: string;
  path: string;
  line: number;
  /** Sanitized, secret-redacted evidence line (capped). */
  evidence: string;
}

const MAX_SNIPPETS = 400;
const MAX_SNIPPET_BYTES = 256 * 1024;
const MAX_LINE = 300;

/** Endpoint extraction (§29/§30): URLs and hosts found in source are
 *  DISCOVERED_REFERENCEs — inventoried, never authorized. */
export function extractMobileEndpoints(snippets: MobileSourceSnippet[], source: string): NormalizedMobileEndpoint[] {
  const seen = new Map<string, NormalizedMobileEndpoint>();
  const urlRe = /\b(https?|wss?):\/\/([A-Za-z0-9.-]+)(?::(\d{1,5}))?(\/[^\s"'<>\\]*)?/g;
  for (const snippet of snippets.slice(0, MAX_SNIPPETS)) {
    const text = snippet.text.slice(0, MAX_SNIPPET_BYTES);
    let m: RegExpExecArray | null;
    while ((m = urlRe.exec(text)) !== null) {
      const scheme = m[1]!.toLowerCase();
      const host = m[2]!.toLowerCase();
      if (host === "schemas.android.com" || host === "www.w3.org" || host.endsWith(".example") || host === "example.com") continue;
      const url = sanitizeMobileText(m[0], 512);
      if (!url || seen.has(url)) continue;
      seen.set(url, {
        url, host,
        kind: scheme === "wss" || scheme === "ws" ? "WEBSOCKET" : scheme === "https" ? "HTTPS" : "HTTP",
        classification: "DISCOVERED_REFERENCE",
        source,
      });
    }
  }
  return [...seen.values()].slice(0, 1000);
}

interface PatternDef {
  ruleId: string;
  pattern: RegExp;
}

const CODE_PATTERNS: PatternDef[] = [
  // §25 WebView: JS bridge exposure + file access from web content.
  { ruleId: "MOBILE_WEBVIEW_JS_BRIDGE", pattern: /addJavascriptInterface\s*\(/ },
  { ruleId: "MOBILE_WEBVIEW_FILE_ACCESS", pattern: /setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)/ },
  // §76 app storage: world-readable modes on app-owned storage.
  { ruleId: "MOBILE_WORLD_READABLE_STORAGE", pattern: /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/ },
  // §85 weak cryptography usage in app code.
  { ruleId: "MOBILE_WEAK_CRYPTOGRAPHY", pattern: /Cipher\.getInstance\(\s*"(?:DES|AES\/ECB|RC4)[^"]*"|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"\s*\)|Mac\.getInstance\(\s*"HmacMD5"/ },
  { ruleId: "MOBILE_INSECURE_RANDOM", pattern: /new\s+Random\s*\(|Math\.random\s*\(/ },
  // §77 logging of sensitive data (heuristic: log call + sensitive term on one line).
  { ruleId: "MOBILE_SENSITIVE_DATA_LOGGING", pattern: /(?:Log\.[diev]|NSLog|print)\s*\([^)]*(?:password|passwd|token|secret|api[_-]?key|authorization)/i },
];

/** Scan decompiled snippets for the §25/§76–§86 risky patterns. Every
 *  observation carries a sanitized, secret-redacted evidence line. */
export function scanMobileSourcePatterns(snippets: MobileSourceSnippet[]): MobilePatternObservation[] {
  const out: MobilePatternObservation[] = [];
  for (const snippet of snippets.slice(0, MAX_SNIPPETS)) {
    const lines = snippet.text.slice(0, MAX_SNIPPET_BYTES).split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx]!;
      for (const def of CODE_PATTERNS) {
        if (def.pattern.test(line)) {
          out.push({
            ruleId: def.ruleId,
            path: sanitizeMobileText(snippet.path, 512),
            line: idx + 1,
            evidence: sanitizeMobileText(redactSecretsInText(line.trim()), MAX_LINE),
          });
        }
      }
      if (out.length >= 500) return out;
    }
  }
  return out;
}

const SECRET_PATTERNS: { type: string; re: RegExp }[] = [
  { type: "API_KEY", re: /\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b/g },
  { type: "GENERIC_SECRET", re: /(?:api[_-]?key|secret|token|password)[A-Za-z0-9_]*\s*[:=]\s*"([A-Za-z0-9_\-./+=]{12,})"/gi },
];

/**
 * Redact secret VALUES from a text blob (§28/§106): decompiled source
 * may ride analysis pipelines as snippets, but a secret value never
 * does — matches are replaced before the text leaves the parser.
 */
export function redactMobileSecretValues(text: string): string {
  let out = redactSecretsInText(text);
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    out = out.replace(p.re, (match, captured?: string) => {
      if (captured && match.includes(captured)) return match.replace(captured, "•••REDACTED•••");
      return "•••REDACTED•••";
    });
  }
  return out;
}

/**
 * Secret scanning over extracted source/resources (§28): reuses the
 * platform secret patterns + fingerprinting. Output findings carry
 * METADATA ONLY — the matched value is consumed by the fingerprint
 * and the redacted preview, then dropped.
 */
export function scanMobileSecrets(
  snippets: MobileSourceSnippet[],
  opts: { applicationRef: string; platform: "ANDROID" | "IOS"; buildHash: string; toolSlug: string },
): NormalizedFinding[] {
  const fingerprints = new SecretFingerprintService();
  const findings: NormalizedFinding[] = [];
  for (const snippet of snippets.slice(0, MAX_SNIPPETS)) {
    const lines = snippet.text.slice(0, MAX_SNIPPET_BYTES).split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx]!;
      for (const p of SECRET_PATTERNS) {
        p.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = p.re.exec(line)) !== null) {
          const value = m[1] ?? m[0];
          if (value.length < 12) continue;
          // Obvious placeholders are not secrets (§28 evidence discipline).
          if (/^(?:example|placeholder|changeme|your[-_ ]|xxx+|\*+|test[-_]?key)/i.test(value)) continue;
          const fingerprint = fingerprints.fingerprint(value);
          findings.push({
            title: `Hardcoded ${p.type === "API_KEY" ? "API key" : "secret"} in decompiled source`,
            description: "A secret-shaped value is embedded in the application package. Embedded secrets are extractable by anyone with the binary; rotate the credential and move it behind a server-side proxy or short-lived token flow. The value itself is never stored by ZeroSweep — metadata only (§28).",
            severity: "HIGH",
            confidence: 0.85,
            cwe: "CWE-798",
            references: [],
            sourceTool: opts.toolSlug,
            sourceFingerprint: fingerprint,
            filePath: sanitizeMobileText(snippet.path, 512),
            startLine: idx + 1,
            endLine: idx + 1,
            ruleId: "MOBILE_HARDCODED_SECRET",
            evidence: `secret ${p.type} detected at ${sanitizeMobileText(snippet.path, 200)}:${idx + 1} (value redacted, §28)`,
            secret: {
              secretType: classifySecretType(p.type),
              detector: "mobile-source-scan",
              fingerprint,
              ...(redactedPreview(value) ? { redactedPreview: redactedPreview(value) } : {}),
              verificationStatus: "NOT_VERIFIED",
            },
          });
        }
      }
      if (findings.length >= 200) return findings;
    }
  }
  return findings;
}
