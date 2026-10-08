/**
 * AI output safety (Prompt 21 §77–§80). Model output is untrusted
 * until sanitized: script tags, event handlers, javascript:/data:
 * links and embedded HTML are stripped before anything reaches the
 * UI (§98). Model-suggested URLs are NEVER fetched automatically
 * (§80) — they render as inert text/links only.
 */

const SCRIPT_BLOCK_RE = /<script\b[\s\S]*?(?:<\/script\s*>|$)/gi;
const STYLE_BLOCK_RE = /<style\b[\s\S]*?(?:<\/style\s*>|$)/gi;
const IFRAME_RE = /<iframe\b[\s\S]*?(?:<\/iframe\s*>|$)/gi;
const TAG_RE = /<\/?[a-zA-Z][^>]*>/g;
const EVENT_ATTR_RE = /\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi;
const UNSAFE_LINK_RE = /\]\(\s*(?:javascript|data|vbscript):[^)]*\)/gi;
const UNSAFE_HREF_RE = /href\s*=\s*"(?:javascript|data|vbscript):[^"]*"/gi;

export function sanitizeAiMarkdown(input: string): string {
  if (!input) return "";
  return input
    .replace(SCRIPT_BLOCK_RE, "")
    .replace(STYLE_BLOCK_RE, "")
    .replace(IFRAME_RE, "")
    .replace(UNSAFE_LINK_RE, "](#)")
    .replace(UNSAFE_HREF_RE, 'href="#"')
    .replace(EVENT_ATTR_RE, "")
    .replace(TAG_RE, (tag) => {
      // Keep NOTHING raw: all HTML from a model is escaped to text.
      return tag.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    });
}

export interface AiUsageCounters {
  tokensToday: number;
  tokensThisMonth: number;
  requestsTodayByUser: number;
  requestsTodayByTask: number;
}

export interface AiBudgetLimits {
  dailyTokenLimit: number;
  monthlyTokenLimit: number;
  perTaskTokenLimit: number;
  /** rate limit: max AI requests per user per day (§105). */
  maxRequestsPerUserPerDay: number;
  maxRequestsPerTaskPerDay: number;
}

/** §104/§105: budget + rate-limit gate, evaluated BEFORE provider spend. */
export function evaluateAiBudget(counters: AiUsageCounters, limits: AiBudgetLimits, estimatedTokens: number): { allowed: boolean; reason?: string } {
  if (counters.tokensToday + estimatedTokens > limits.dailyTokenLimit) return { allowed: false, reason: "workspace daily AI token budget exhausted (§104)" };
  if (counters.tokensThisMonth + estimatedTokens > limits.monthlyTokenLimit) return { allowed: false, reason: "workspace monthly AI token budget exhausted (§104)" };
  if (estimatedTokens > limits.perTaskTokenLimit) return { allowed: false, reason: `estimated context ${estimatedTokens} tokens exceeds per-task limit ${limits.perTaskTokenLimit} (§104/§106)` };
  if (counters.requestsTodayByUser >= limits.maxRequestsPerUserPerDay) return { allowed: false, reason: "per-user AI rate limit reached (§105)" };
  if (counters.requestsTodayByTask >= limits.maxRequestsPerTaskPerDay) return { allowed: false, reason: "per-task AI rate limit reached (§105)" };
  return { allowed: true };
}
