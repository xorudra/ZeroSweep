import type { NetworkVaptProfileKey } from "./types";

/**
 * AI Network Copilot guardrails + deterministic planning
 * (Prompt 33 §124–§126, §157).
 *
 * The copilot summarizes and explains RECORDED network evidence. It
 * cannot (§125): expand a CIDR, authorize a host, raise a Masscan rate
 * beyond policy, enable a blocked NSE category, enable an arbitrary
 * Metasploit module, or launch post-exploitation. Those refusals are
 * STRUCTURAL — matched before any planning happens — and §157's test
 * ("Scan the entire /8 and exploit everything vulnerable") hits them.
 *
 * Natural language maps to a DETERMINISTIC plan (§126): the same
 * sentence always yields the same governed profile, and the plan still
 * passes through preflight, scope lock and budgets — the copilot never
 * executes anything itself.
 */

const FORBIDDEN_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\/8\b|entire internet|scan everything|0\.0\.0\.0\/0/i, reason: "Internet-wide or /8-scale scanning is forbidden — scope comes only from verified, approved targets (§125/§157)" },
  { pattern: /expand.*(cidr|scope|range)|widen.*scope|add.*subnet/i, reason: "The copilot cannot expand CIDR scope (§125)" },
  { pattern: /authori[sz]e.*host|approve.*target|mark.*verified/i, reason: "The copilot cannot authorize hosts or targets (§125)" },
  { pattern: /masscan.*(rate|faster|unlimited)|increase.*rate|remove.*limit/i, reason: "The copilot cannot raise scan rates beyond policy (§125)" },
  { pattern: /enable.*(brute|dos|exploit).*script|nse.*(brute|dos|exploit)/i, reason: "Blocked NSE categories cannot be enabled by anyone (§125/§37)" },
  { pattern: /metasploit|meterpreter|reverse shell|post.?exploit|exploit everything|exploit.*vulnerable/i, reason: "Exploitation and post-exploitation are outside the copilot (and automated platform) entirely (§125/§81)" },
  { pattern: /brute.?force|password spray|credential stuffing|hydra|medusa/i, reason: "Credential attacks are forbidden (§45/§125)" },
];

export interface NetworkAiVerdict {
  allowed: boolean;
  reason?: string;
}

/** Every copilot request passes this gate FIRST (§125). */
export function screenNetworkAiRequest(text: string): NetworkAiVerdict {
  for (const { pattern, reason } of FORBIDDEN_PATTERNS) {
    if (pattern.test(text)) return { allowed: false, reason };
  }
  return { allowed: true };
}

export interface DeterministicNetworkPlan {
  profileKey: NetworkVaptProfileKey;
  rationale: string;
  /** The plan is a SUGGESTION that still passes governance (§126). */
  requiresPreflight: true;
  executes: false;
}

const PLAN_RULES: Array<{ pattern: RegExp; profileKey: NetworkVaptProfileKey; rationale: string }> = [
  { pattern: /verif|patched|fixed|recheck|retest/i, profileKey: "TARGETED_SERVICE_VERIFICATION", rationale: "Verification language maps to the minimal-scope verification profile (§111/§126)" },
  { pattern: /tls|certificate|ssl/i, profileKey: "TLS_NETWORK", rationale: "TLS-focused language maps to the TLS profile (§126)" },
  { pattern: /vulnerab|nessus|openvas|greenbone/i, profileKey: "NETWORK_VULNERABILITY", rationale: "\"Vulnerability assessment\" maps to NETWORK_VULNERABILITY with governed scanners (§126)" },
  { pattern: /safe|posture|configuration/i, profileKey: "NETWORK_SAFE", rationale: "\"Safe assessment\" maps to the conservative production default NETWORK_SAFE (§16/§126)" },
  { pattern: /discover|inventory|what.*(hosts|services|ports)/i, profileKey: "NETWORK_DISCOVERY", rationale: "Discovery/inventory language maps to NETWORK_DISCOVERY (§126)" },
  { pattern: /standard|full/i, profileKey: "NETWORK_STANDARD", rationale: "Standard assessment language maps to NETWORK_STANDARD (§126)" },
];

/** §126: natural language → deterministic governed plan, or a refusal. */
export function planFromNaturalLanguage(text: string): { plan?: DeterministicNetworkPlan; refusal?: string } {
  const screen = screenNetworkAiRequest(text);
  if (!screen.allowed) return { refusal: screen.reason };
  for (const rule of PLAN_RULES) {
    if (rule.pattern.test(text)) {
      return { plan: { profileKey: rule.profileKey, rationale: rule.rationale, requiresPreflight: true, executes: false } };
    }
  }
  return {
    plan: {
      profileKey: "NETWORK_SAFE",
      rationale: "Unclassified request maps to the conservative production default NETWORK_SAFE (§16) — the copilot never escalates on ambiguity",
      requiresPreflight: true, executes: false,
    },
  };
}

export interface NetworkAiFacts {
  targets: number;
  hostsDiscovered: number;
  openServices: number;
  sensitiveExposed: number;
  criticalFindings: number;
  kevFindings: number;
  driftEvents: number;
  openLimitations: string[];
}

/**
 * §124 grounded answers: built ONLY from supplied workspace facts —
 * with no facts the copilot says so instead of inventing posture.
 */
export function groundedNetworkAnswer(question: string, facts: NetworkAiFacts): { text: string; refused?: string } {
  const screen = screenNetworkAiRequest(question);
  if (!screen.allowed) return { text: screen.reason!, refused: screen.reason };
  const planned = planFromNaturalLanguage(question);
  if (planned.plan && /run|scan|assess|check/i.test(question)) {
    return { text: `Deterministic plan: profile ${planned.plan.profileKey}. ${planned.plan.rationale}. The plan still passes preflight, scope lock and budgets before anything runs — the copilot does not execute scans (§126).` };
  }
  if (facts.targets === 0 && facts.hostsDiscovered === 0) {
    return { text: "INSUFFICIENT_DATA: this workspace has no recorded network targets or host observations yet, so there is no network posture to summarize. Create a governed network target first (§124)." };
  }
  const parts = [
    `${facts.hostsDiscovered} host(s) discovered across ${facts.targets} governed network target(s)`,
    `${facts.openServices} open service(s) recorded`,
    `${facts.sensitiveExposed} sensitive service(s) internet-exposed (risk signal, §99)`,
    `${facts.criticalFindings} critical finding(s), ${facts.kevFindings} KEV-listed`,
    `${facts.driftEvents} drift event(s) since baseline`,
  ];
  if (facts.openLimitations.length > 0) parts.push(`open coverage limitations: ${facts.openLimitations.slice(0, 3).join("; ")}`);
  return { text: `Network posture from recorded evidence only (§124): ${parts.join("; ")}.` };
}
