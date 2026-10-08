import { parseSecurityQueryDsl, type DslNode } from "./dsl";

/**
 * AI security intelligence over analytics (Prompt 27 §104–§109).
 *
 * The AI layer NEVER writes SQL (§109) and NEVER invents numbers
 * (§106): natural language is translated deterministically into the
 * governed DSL (§108), executed by the deterministic engine, and
 * trend explanations cite ONLY the metric values they are handed.
 * With insufficient history the answer is INSUFFICIENT_DATA (§141) —
 * mirroring the copilot's INSUFFICIENT_EVIDENCE discipline.
 */

export type NlToDslResult = { dsl: string; ast: DslNode; notes: string[] } | { rejected: string };

const SQL_SHAPE_RE = /(\bunion\s+select\b|\bdrop\s+table\b|\binsert\s+into\b|\bdelete\s+from\b|' or '1'='1|\bor\s+1\s*=\s*1\b)/i;

export function translateNlToDsl(question: string): NlToDslResult {
  if (SQL_SHAPE_RE.test(question)) {
    return { rejected: "question contains SQL-shaped syntax; the analytics copilot translates plain language into the governed DSL only (§109)" };
  }
  const q = ` ${question.toLowerCase()} `;
  const clauses: string[] = [];
  const notes: string[] = [];
  if (/\bcritical\b/.test(q)) { clauses.push("severity:critical"); notes.push("severity = CRITICAL"); }
  else if (/\bhigh\b/.test(q)) { clauses.push("severity:high"); notes.push("severity = HIGH"); }
  if (/\bpublic|internet|exposed|external\b/.test(q)) { clauses.push("internet_exposed:true"); notes.push("internet-exposed only"); }
  if (/\bkev|known exploited\b/.test(q)) { clauses.push("kev:true"); notes.push("KEV-listed only"); }
  if (/\bverified|confirmed\b/.test(q)) { clauses.push("verified:true"); notes.push("verified only"); }
  if (/\bopen\b/.test(q)) { clauses.push("status:open"); notes.push("open status"); }
  const cve = /\bcve-\d{4}-\d{4,}\b/i.exec(question);
  if (cve) { clauses.push(`cve:${cve[0].toLowerCase()}`); notes.push(`CVE ${cve[0].toUpperCase()}`); }
  const cwe = /\bcwe-\d+\b/i.exec(question);
  if (cwe) { clauses.push(`cwe:${cwe[0].toLowerCase()}`); notes.push(`CWE ${cwe[0].toUpperCase()}`); }
  const tech = /\bwordpress|nginx|apache|openssl|log4j|kubernetes|docker|postgres|mysql|redis\b/i.exec(question);
  if (tech) { clauses.push(`technology:${tech[0].toLowerCase()}`); notes.push(`technology ${tech[0].toLowerCase()}`); }
  const risk = /\brisk\s*(?:>=|above|over)\s*(\d{1,3})\b/.exec(q);
  if (risk) { clauses.push(`risk:>=${risk[1]}`); notes.push(`risk >= ${risk[1]}`); }
  if (!clauses.length) {
    return { rejected: "could not map the question to the governed analytics DSL — name a severity, exposure, KEV, CVE/CWE, technology or risk bound (§108)" };
  }
  const dsl = clauses.join(" ");
  const parsed = parseSecurityQueryDsl(dsl);
  if ("rejected" in parsed) return { rejected: parsed.rejected };
  return { dsl, ast: parsed.ast, notes };
}

export interface TrendExplanation {
  status: "OK" | "INSUFFICIENT_DATA";
  text: string;
  citations: Array<{ kind: string; ref: string }>;
}

/**
 * §105/§106/§140/§141: explain a trend using ONLY the deterministic
 * values supplied. Fewer than 2 series points, or a missing previous
 * period, yields INSUFFICIENT_DATA — never an invented change.
 */
export function explainTrend(input: {
  metric: string;
  seriesPoints: number;
  current: number | null;
  previous: number | null;
  rangeLabel: string;
}): TrendExplanation {
  if (input.seriesPoints < 2 || input.current === null || input.previous === null) {
    return {
      status: "INSUFFICIENT_DATA",
      text: `INSUFFICIENT_DATA: not enough recorded history to explain the ${input.metric} trend over ${input.rangeLabel}. The metric is computed from recorded analytics events only, and the available series has ${input.seriesPoints} point(s).`,
      citations: [{ kind: "ANALYTICS_METRIC", ref: input.metric }],
    };
  }
  const delta = input.current - input.previous;
  const direction = delta > 0 ? "increased" : delta < 0 ? "decreased" : "did not change";
  const pct = input.previous === 0 ? null : Math.round((delta / input.previous) * 1000) / 10;
  return {
    status: "OK",
    text: `${input.metric} ${direction} from ${input.previous} to ${input.current} (${delta >= 0 ? "+" : ""}${delta}${pct === null ? "" : `, ${pct >= 0 ? "+" : ""}${pct}%`}) over ${input.rangeLabel}. These figures are the deterministic analytics values recorded for the two periods.`,
    citations: [{ kind: "ANALYTICS_METRIC", ref: input.metric }],
  };
}

/** §107: explain a stored attack-path candidate from its evidence — no exploit steps, ever. */
export function explainAttackPath(path: { title: string; score: number; confidence: string; nodes: readonly { kind: string; label: string }[]; edges: readonly { evidenceType: string; evidenceId: string }[] }): string {
  const chain = path.nodes.map((n) => `${n.kind}: ${n.label}`).join(" → ");
  const evidence = path.edges.map((e) => `${e.evidenceType} ${e.evidenceId}`).join(", ");
  return `Analytical attack-path candidate (score ${path.score}, confidence ${path.confidence}): ${chain}. Every step is backed by stored evidence (${evidence}). This is correlation over observed relationships and findings — not an exploitation procedure.`;
}
