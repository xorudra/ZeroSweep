import type { CanonicalTelemetryEvent, DetectionConfidence, DetectionType } from "./types";

/**
 * Detection rule DSL (Prompt 28 §17–§24). Rules are DECLARATIVE
 * JSON compiled into a typed AST and evaluated over canonical
 * telemetry events. There is no eval, no SQL, no shell, no script
 * anywhere in the pipeline (§18): definitions containing code-like
 * content are rejected at compile time (§134), and complexity is
 * bounded (§24/§135) — conditions, nesting, sequence length, window
 * size and grouping fields are all allowlisted and capped.
 */

export type RuleOperator = "eq" | "neq" | "in" | "notIn" | "contains" | "gt" | "gte" | "lt" | "lte" | "cidrContains" | "exists";
export const RULE_OPERATORS: readonly RuleOperator[] = ["eq", "neq", "in", "notIn", "contains", "gt", "gte", "lt", "lte", "cidrContains", "exists"];

export type RuleNode =
  | { kind: "cond"; field: string; op: RuleOperator; value?: unknown }
  | { kind: "all" | "any"; children: RuleNode[] };

export interface DetectionRuleDefinition {
  type: DetectionType;
  conditions: RuleNode;
  windowSeconds?: number;
  threshold?: { count: number; groupBy?: string };
  sequence?: RuleNode[];
  anomaly?: { metricField: string; minSamples: number; zScore: number };
}

export const RULE_LIMITS = {
  maxConditions: 32,
  maxDepth: 4,
  maxSequenceSteps: 8,
  minWindowSeconds: 10,
  maxWindowSeconds: 7 * 24 * 3600,
  maxThresholdCount: 10000,
  maxGroupCardinality: 1000,
} as const;

const BASE_FIELDS = new Set([
  "source", "sourceCategory", "eventCategory", "eventAction", "severity",
  "classification", "assetId", "identityReference", "eventTime",
]);
const GROUP_BY_FIELDS = new Set(["identityReference", "assetId", "source", "eventAction", "attributes.sourceIp"]);

/** §18/§134: code-bearing content is rejected wherever it appears in
 *  a rule definition — keys, field names and match values alike. */
const FORBIDDEN_TOKEN = /\b(eval|exec|shell|script|sql|powershell|cmd\.exe|bash|sh)\b/i;
const FORBIDDEN_CHARS = /[`;]|(\$\()|(\$\{)|(--)|(\/\*)/;

export function fieldAllowed(field: string): boolean {
  if (BASE_FIELDS.has(field)) return true;
  if (field.startsWith("attributes.")) {
    const key = field.slice("attributes.".length);
    return /^[a-zA-Z0-9_-]{1,48}$/.test(key);
  }
  return false;
}

function scanForbidden(value: unknown, errors: string[], path: string): void {
  if (typeof value === "string") {
    if (FORBIDDEN_TOKEN.test(value) || FORBIDDEN_CHARS.test(value)) errors.push(`FORBIDDEN_CONTENT:${path}`);
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => scanForbidden(v, errors, `${path}[${i}]`));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_TOKEN.test(k) || FORBIDDEN_CHARS.test(k)) errors.push(`FORBIDDEN_CONTENT:${path}.${k}`);
      scanForbidden(v, errors, `${path}.${k}`);
    }
  }
}

function validateNode(node: unknown, errors: string[], depth: number, counter: { count: number }): RuleNode | null {
  if (depth > RULE_LIMITS.maxDepth) { errors.push("RULE_TOO_DEEP"); return null; }
  if (!node || typeof node !== "object" || Array.isArray(node)) { errors.push("RULE_NODE_INVALID"); return null; }
  const n = node as Record<string, unknown>;
  if (n.kind === "all" || n.kind === "any") {
    if (!Array.isArray(n.children) || n.children.length === 0 || n.children.length > 16) { errors.push("RULE_GROUP_INVALID"); return null; }
    const children: RuleNode[] = [];
    for (const child of n.children) {
      const c = validateNode(child, errors, depth + 1, counter);
      if (c) children.push(c);
    }
    return { kind: n.kind, children };
  }
  if (n.kind === "cond") {
    counter.count += 1;
    if (counter.count > RULE_LIMITS.maxConditions) { errors.push("RULE_TOO_MANY_CONDITIONS"); return null; }
    const field = n.field as string;
    if (typeof field !== "string" || !fieldAllowed(field)) { errors.push(`RULE_FIELD_NOT_ALLOWED:${String(field)}`); return null; }
    const op = n.op as RuleOperator;
    if (!RULE_OPERATORS.includes(op)) { errors.push(`RULE_OPERATOR_NOT_ALLOWED:${String(op)}`); return null; }
    if (op !== "exists" && n.value === undefined) { errors.push("RULE_VALUE_REQUIRED"); return null; }
    if ((op === "in" || op === "notIn") && (!Array.isArray(n.value) || n.value.length === 0 || n.value.length > 64)) { errors.push("RULE_SET_INVALID"); return null; }
    if (op === "cidrContains" && (typeof n.value !== "string" || !/^\d{1,3}(\.\d{1,3}){0,3}(\/\d{1,2})?$/.test(n.value))) { errors.push("RULE_CIDR_INVALID"); return null; }
    return { kind: "cond", field, op, value: n.value };
  }
  errors.push("RULE_NODE_KIND_UNKNOWN");
  return null;
}

export interface CompiledRule { ok: boolean; errors: string[]; definition?: DetectionRuleDefinition }

/** Compile + validate a rule definition (§19). Never throws. */
export function compileDetectionRule(input: unknown): CompiledRule {
  const errors: string[] = [];
  if (!input || typeof input !== "object" || Array.isArray(input)) return { ok: false, errors: ["RULE_NOT_OBJECT"] };
  scanForbidden(input, errors, "rule");
  const r = input as Record<string, unknown>;
  const type = r.type as DetectionType;
  if (!["SINGLE_EVENT", "THRESHOLD", "SEQUENCE", "CORRELATION", "ANOMALY_SIGNAL"].includes(type)) {
    errors.push("RULE_TYPE_UNKNOWN");
    return { ok: false, errors };
  }
  const counter = { count: 0 };
  const conditions = validateNode(r.conditions, errors, 0, counter);
  const definition: DetectionRuleDefinition = { type, conditions: conditions ?? { kind: "all", children: [] } };

  const windowSeconds = r.windowSeconds as number | undefined;
  if (type === "THRESHOLD" || type === "SEQUENCE") {
    if (typeof windowSeconds !== "number" || windowSeconds < RULE_LIMITS.minWindowSeconds || windowSeconds > RULE_LIMITS.maxWindowSeconds) {
      errors.push("RULE_WINDOW_OUT_OF_BOUNDS");
    } else definition.windowSeconds = windowSeconds;
  } else if (windowSeconds !== undefined) {
    if (typeof windowSeconds !== "number" || windowSeconds < 0 || windowSeconds > RULE_LIMITS.maxWindowSeconds) errors.push("RULE_WINDOW_OUT_OF_BOUNDS");
    else definition.windowSeconds = windowSeconds;
  }
  if (type === "THRESHOLD") {
    const t = r.threshold as { count?: unknown; groupBy?: unknown } | undefined;
    if (!t || typeof t.count !== "number" || t.count < 2 || t.count > RULE_LIMITS.maxThresholdCount) errors.push("RULE_THRESHOLD_INVALID");
    else {
      definition.threshold = { count: t.count };
      if (t.groupBy !== undefined) {
        if (typeof t.groupBy !== "string" || !GROUP_BY_FIELDS.has(t.groupBy)) errors.push("RULE_GROUPBY_NOT_ALLOWED");
        else definition.threshold.groupBy = t.groupBy;
      }
    }
  }
  if (type === "SEQUENCE") {
    if (!Array.isArray(r.sequence) || r.sequence.length < 2 || r.sequence.length > RULE_LIMITS.maxSequenceSteps) {
      errors.push("RULE_SEQUENCE_LENGTH_INVALID");
    } else {
      const steps: RuleNode[] = [];
      for (const s of r.sequence) { const v = validateNode(s, errors, 0, counter); if (v) steps.push(v); }
      definition.sequence = steps;
    }
  }
  if (type === "ANOMALY_SIGNAL") {
    const a = r.anomaly as { metricField?: unknown; minSamples?: unknown; zScore?: unknown } | undefined;
    if (!a || typeof a.metricField !== "string" || !a.metricField.startsWith("attributes.")
      || typeof a.minSamples !== "number" || a.minSamples < 5 || a.minSamples > 100000
      || typeof a.zScore !== "number" || a.zScore < 1 || a.zScore > 10) {
      errors.push("RULE_ANOMALY_INVALID");
    } else {
      definition.anomaly = { metricField: a.metricField, minSamples: a.minSamples, zScore: a.zScore };
    }
  }
  if (errors.length > 0) return { ok: false, errors: [...new Set(errors)] };
  return { ok: true, errors: [], definition };
}

/* ------------------------------ evaluation ------------------------------ */

export function resolveField(event: CanonicalTelemetryEvent, field: string): unknown {
  if (field.startsWith("attributes.")) return event.attributes[field.slice("attributes.".length)];
  return (event as unknown as Record<string, unknown>)[field];
}

function ipToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) { const v = Number(p); if (!Number.isInteger(v) || v < 0 || v > 255) return null; n = n * 256 + v; }
  return n >>> 0;
}

function cidrMatch(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  const ipN = ipToInt(ip); const baseN = ipToInt(base);
  if (ipN === null || baseN === null || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipN & mask) === (baseN & mask);
}

export function matchRuleNode(node: RuleNode, event: CanonicalTelemetryEvent): boolean {
  if (node.kind !== "cond") {
    return node.kind === "all"
      ? node.children.every((c) => matchRuleNode(c, event))
      : node.children.some((c) => matchRuleNode(c, event));
  }
  const actual = resolveField(event, node.field);
  const v = node.value;
  switch (node.op) {
    case "exists": return actual !== undefined && actual !== null;
    case "eq": return actual === v;
    case "neq": return actual !== v;
    case "in": return Array.isArray(v) && v.includes(actual as never);
    case "notIn": return Array.isArray(v) && !v.includes(actual as never);
    case "contains": return typeof actual === "string" && typeof v === "string" && actual.toLowerCase().includes(v.toLowerCase());
    case "gt": return typeof actual === "number" && typeof v === "number" && actual > v;
    case "gte": return typeof actual === "number" && typeof v === "number" && actual >= v;
    case "lt": return typeof actual === "number" && typeof v === "number" && actual < v;
    case "lte": return typeof actual === "number" && typeof v === "number" && actual <= v;
    case "cidrContains": return typeof actual === "string" && typeof v === "string" && cidrMatch(actual, v);
    default: return false;
  }
}

export interface WindowMatch {
  groupKey: string;
  events: CanonicalTelemetryEvent[];
  count: number;
  windowStart: string;
  windowEnd: string;
}

/** §21: threshold evaluation over a bounded, time-sorted window. */
export function evaluateThreshold(definition: DetectionRuleDefinition, events: CanonicalTelemetryEvent[]): WindowMatch[] {
  if (!definition.threshold || !definition.windowSeconds) return [];
  const matching = events.filter((e) => matchRuleNode(definition.conditions, e))
    .sort((a, b) => a.eventTime.localeCompare(b.eventTime));
  const groups = new Map<string, CanonicalTelemetryEvent[]>();
  for (const e of matching) {
    const key = definition.threshold.groupBy ? String(resolveField(e, definition.threshold.groupBy) ?? "∅") : "all";
    const list = groups.get(key) ?? [];
    list.push(e);
    groups.set(key, list);
  }
  const out: WindowMatch[] = [];
  for (const [key, list] of groups) {
    if (groups.size > RULE_LIMITS.maxGroupCardinality) break;
    let start = 0;
    let latest: WindowMatch | null = null;
    for (let end = 0; end < list.length; end++) {
      const endT = new Date(list[end].eventTime).getTime();
      while (endT - new Date(list[start].eventTime).getTime() > definition.windowSeconds * 1000) start++;
      const count = end - start + 1;
      if (count >= definition.threshold.count) {
        // Keep the MOST RECENT satisfying window per group: live
        // evaluation asks "does the window ending at the newest
        // event satisfy the threshold" — the earliest historical
        // window would mask fresh activity behind old matches.
        latest = { groupKey: key, events: list.slice(start, end + 1), count, windowStart: list[start].eventTime, windowEnd: list[end].eventTime };
      }
    }
    if (latest) out.push(latest);
  }
  return out;
}

/** §22: ordered sequence evaluation. Wrong order ⇒ no match (§133). */
export function evaluateSequence(definition: DetectionRuleDefinition, events: CanonicalTelemetryEvent[]): { events: CanonicalTelemetryEvent[] } | null {
  if (!definition.sequence || !definition.windowSeconds) return null;
  const sorted = [...events].sort((a, b) => a.eventTime.localeCompare(b.eventTime));
  const chain: CanonicalTelemetryEvent[] = [];
  let cursor = 0;
  for (const step of definition.sequence) {
    let found: CanonicalTelemetryEvent | null = null;
    while (cursor < sorted.length) {
      const candidate = sorted[cursor++];
      if (matchRuleNode(step, candidate)) { found = candidate; break; }
    }
    if (!found) return null;
    chain.push(found);
  }
  const span = new Date(chain[chain.length - 1].eventTime).getTime() - new Date(chain[0].eventTime).getTime();
  if (span > definition.windowSeconds * 1000) return null;
  return { events: chain };
}

/** §20: anomaly signals are statistical and EXPLAINABLE — the reason
 *  always carries the numbers, and insufficient baseline data never
 *  produces a signal. */
export function evaluateAnomaly(
  definition: DetectionRuleDefinition,
  event: CanonicalTelemetryEvent,
  baseline: { mean: number; stdDev: number; samples: number },
): { matched: boolean; reason: string } {
  if (!definition.anomaly) return { matched: false, reason: "no anomaly configuration" };
  const value = resolveField(event, definition.anomaly.metricField);
  if (typeof value !== "number") return { matched: false, reason: `metric ${definition.anomaly.metricField} is not numeric on this event` };
  if (baseline.samples < definition.anomaly.minSamples) {
    return { matched: false, reason: `insufficient baseline: ${baseline.samples} samples < ${definition.anomaly.minSamples} required — no signal emitted` };
  }
  if (baseline.stdDev <= 0) return { matched: false, reason: "baseline has zero variance — no signal emitted" };
  const z = Math.abs((value - baseline.mean) / baseline.stdDev);
  const matched = z >= definition.anomaly.zScore;
  return {
    matched,
    reason: `metric=${value} baseline mean=${baseline.mean} stdDev=${baseline.stdDev} samples=${baseline.samples} z=${z.toFixed(2)} threshold=${definition.anomaly.zScore}`,
  };
}

/** §29: deterministic confidence from evidence quality. */
export function detectionConfidence(input: {
  type: DetectionType;
  thresholdCount?: number;
  thresholdRequired?: number;
  severity: string;
  intelConfidence?: number; // 0..100 when threat intel contributed
}): DetectionConfidence {
  if (input.type === "SEQUENCE") return "HIGH";
  if (input.type === "THRESHOLD" && input.thresholdCount !== undefined && input.thresholdRequired !== undefined) {
    if (input.thresholdCount >= input.thresholdRequired * 2) return "HIGH";
    return "MEDIUM";
  }
  if (input.intelConfidence !== undefined) {
    if (input.intelConfidence >= 70) return "HIGH";
    if (input.intelConfidence >= 40) return "MEDIUM";
    return "LOW"; // §69: one low-confidence feed never yields certainty
  }
  if (input.severity === "CRITICAL" || input.severity === "HIGH") return "MEDIUM";
  return "LOW";
}
