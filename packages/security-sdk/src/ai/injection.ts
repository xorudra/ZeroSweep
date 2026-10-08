/**
 * Prompt-injection detection (Prompt 21 §18/§20/§72/§92). ALL scanner
 * data, evidence text, imported findings, SSIDs, binary/mobile strings
 * and knowledge documents are UNTRUSTED. Detection does NOT silently
 * delete legitimate evidence (§20): it flags the record, which lowers
 * trust/confidence signals and is counted on the request log (§118).
 * The structural defense is instruction/data separation (§19) — this
 * detector is the tripwire, not the wall.
 */

export interface InjectionDetection {
  pattern: string;
  excerpt: string;
}

export interface InjectionScanResult {
  detections: InjectionDetection[];
  /** 0..1 trust multiplier for the scanned text (1 = no detections). */
  trustScore: number;
}

const PATTERNS: { name: string; re: RegExp }[] = [
  { name: "IGNORE_INSTRUCTIONS", re: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)/i },
  { name: "DISREGARD_INSTRUCTIONS", re: /disregard\s+(all\s+)?(previous|prior|above|the)\s+(instructions|prompts?|rules|system)/i },
  { name: "SYSTEM_PROMPT_REQUEST", re: /(reveal|show|print|output|repeat)\s+(your\s+)?(system\s+prompt|instructions|prompt)/i },
  { name: "ROLE_OVERRIDE", re: /you\s+are\s+now\s+(a|an|in)\b/i },
  { name: "NEW_INSTRUCTIONS", re: /\bnew\s+instructions?\s*:/i },
  { name: "TOOL_EXECUTION_REQUEST", re: /(run|execute|call)\s+(the\s+)?(shell|terminal|command|tool|function)\b/i },
  { name: "CREDENTIAL_REQUEST", re: /(reveal|show|leak|send|give)\s+(me\s+)?(the\s+)?(password|api\s?key|token|secret|credential|private\s+key)/i },
  { name: "POLICY_BYPASS", re: /(bypass|disable|override)\s+(the\s+)?(security\s+)?(policy|policies|guardrails?|filter|controls?)/i },
  { name: "DELIMITER_SPOOF", re: /(SYSTEM\s+POLICY|END\s+OF\s+(SYSTEM|INSTRUCTIONS)|<\|im_(start|end)\|>|\[INST\]|\[\/INST\])/i },
];

/** Long base64-looking blocks are a common encoded-instruction carrier (§20). */
const ENCODED_BLOCK_RE = /\b[A-Za-z0-9+/]{120,}={0,2}\b/;

export function scanForInjection(text: string): InjectionScanResult {
  const detections: InjectionDetection[] = [];
  if (!text) return { detections, trustScore: 1 };
  for (const p of PATTERNS) {
    const m = text.match(p.re);
    if (m) detections.push({ pattern: p.name, excerpt: m[0].slice(0, 80) });
  }
  if (ENCODED_BLOCK_RE.test(text)) {
    // Only flag when the decoded payload actually reads like an
    // instruction — raw hashes/digests are long base64-ish strings too
    // and must not be penalized (§20: do not harm legitimate evidence).
    try {
      const block = text.match(ENCODED_BLOCK_RE)![0];
      const decoded = Buffer.from(block, "base64").toString("utf8");
      if (PATTERNS.some((p) => p.re.test(decoded))) {
        detections.push({ pattern: "ENCODED_INSTRUCTION_BLOCK", excerpt: block.slice(0, 40) });
      }
    } catch { /* undecodable — not an instruction carrier */ }
  }
  const trustScore = Math.max(0.1, 1 - 0.3 * detections.length);
  return { detections, trustScore };
}
