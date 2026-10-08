/**
 * SecurityQueryDSL (Prompt 27 §34–§38).
 *
 * A deterministic parser from DSL text to a TYPED AST. The AST is the
 * only thing that ever reaches execution, and execution is an
 * in-memory evaluation over rows the caller has ALREADY tenant-scoped
 * — the DSL text is never converted into SQL (§35), never evaluated
 * as code, and supports no regex (§38). Hostile input (SQL syntax,
 * Lucene syntax, HTML, control characters) is treated as inert TERM
 * data (§125) or rejected by the complexity limits (§37/§126).
 */

export type DslNode =
  | { kind: "AND"; children: DslNode[] }
  | { kind: "OR"; children: DslNode[] }
  | { kind: "NOT"; child: DslNode }
  | { kind: "FIELD_FILTER"; field: string; op: "eq" | "neq" | "in"; value: string | string[] }
  | { kind: "RANGE"; field: string; op: "gte" | "lte" | "gt" | "lt"; value: number }
  | { kind: "TERM"; value: string }
  | { kind: "DATE_RANGE"; from?: string; to?: string };

export const DSL_LIMITS = {
  maxQueryLength: 512,
  maxClauses: 32,
  maxDepth: 5,
  maxTermLength: 128,
  maxResultWindow: 500,
} as const;

/** Fields a FIELD_FILTER / RANGE may address. Anything else is rejected. */
export const DSL_FIELDS = [
  "severity", "priority", "status", "lifecycle_status", "kev", "internet_exposed",
  "technology", "cve", "cwe", "risk", "type", "source", "verified",
  "repository", "control", "framework", "classification", "asset", "event_type",
] as const;
const FIELD_SET = new Set<string>(DSL_FIELDS);
const RANGE_FIELDS = new Set(["risk"]);
const BOOL_FIELDS = new Set(["kev", "internet_exposed", "verified"]);

export type DslParseResult = { ast: DslNode; clauseCount: number } | { rejected: string };

interface Token { kind: "LPAREN" | "RPAREN" | "AND" | "OR" | "NOT" | "WORD"; value?: string }

function tokenize(input: string): Token[] | { error: string } {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i]!;
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === "(") { tokens.push({ kind: "LPAREN" }); i++; continue; }
    if (ch === ")") { tokens.push({ kind: "RPAREN" }); i++; continue; }
    // Word: run of non-space, non-paren characters; quoted segments keep spaces.
    let word = "";
    while (i < input.length && !/[\s()]/.test(input[i]!)) {
      if (input[i] === '"') {
        i++;
        while (i < input.length && input[i] !== '"') { word += input[i]; i++; }
        if (i >= input.length) return { error: "unterminated quoted value" };
        i++; // closing quote
      } else { word += input[i]; i++; }
    }
    if (word.length > DSL_LIMITS.maxTermLength) return { error: "term exceeds maximum length" };
    const upper = word.toUpperCase();
    if (upper === "AND" || upper === "OR" || upper === "NOT") tokens.push({ kind: upper });
    else tokens.push({ kind: "WORD", value: word });
  }
  return tokens;
}

function parseWord(word: string): DslNode | { error: string } {
  const m = /^([A-Za-z_][A-Za-z0-9_]*):(.*)$/.exec(word);
  if (!m) {
    // Bare term — inert text data (§125). Control characters are stripped.
    const clean = [...word].filter((ch) => { const c = ch.charCodeAt(0); return c > 0x1f && c !== 0x7f; }).join("").trim();
    if (!clean) return { error: "empty term" };
    return { kind: "TERM", value: clean.toLowerCase() };
  }
  const field = m[1]!.toLowerCase();
  let value = m[2]!;
  if (!FIELD_SET.has(field)) return { error: `unknown DSL field: ${field}` };
  const range = /^(>=|<=|>|<)(.+)$/.exec(value);
  if (range) {
    if (!RANGE_FIELDS.has(field)) return { error: `range operator not allowed on field: ${field}` };
    const num = Number(range[2]);
    if (!Number.isFinite(num)) return { error: `range value is not a number: ${range[2]}` };
    const op = range[1] === ">=" ? "gte" : range[1] === "<=" ? "lte" : range[1] === ">" ? "gt" : "lt";
    return { kind: "RANGE", field, op, value: num };
  }
  if (value.includes(",")) {
    const parts = value.split(",").map((p) => p.trim().toLowerCase()).filter(Boolean);
    if (!parts.length || parts.length > 16) return { error: "invalid value list" };
    return { kind: "FIELD_FILTER", field, op: "in", value: parts };
  }
  value = value.toLowerCase();
  if (BOOL_FIELDS.has(field) && value !== "true" && value !== "false") return { error: `boolean field ${field} requires true|false` };
  return { kind: "FIELD_FILTER", field, op: "eq", value };
}

export function parseDateSugar(field: string, value: string): DslNode | null {
  if (field === "after") { const d = new Date(value); return Number.isNaN(d.getTime()) ? null : { kind: "DATE_RANGE", from: d.toISOString() }; }
  if (field === "before") { const d = new Date(value); return Number.isNaN(d.getTime()) ? null : { kind: "DATE_RANGE", to: d.toISOString() }; }
  return null;
}

export function parseSecurityQueryDsl(input: string): DslParseResult {
  if (typeof input !== "string" || !input.trim()) return { rejected: "query is empty" };
  if (input.length > DSL_LIMITS.maxQueryLength) return { rejected: `query exceeds ${DSL_LIMITS.maxQueryLength} characters (§37)` };
  const toks = tokenize(input);
  if (!Array.isArray(toks)) return { rejected: toks.error };
  if (!toks.length) return { rejected: "query is empty" };

  let pos = 0;
  let clauses = 0;
  const peek = () => toks[pos];
  const next = () => toks[pos++];

  function parsePrimary(depth: number): DslNode | { error: string } {
    if (depth > DSL_LIMITS.maxDepth) return { error: `query nesting exceeds depth ${DSL_LIMITS.maxDepth} (§37/§126)` };
    const t = peek();
    if (!t) return { error: "unexpected end of query" };
    if (t.kind === "NOT") { next(); const child = parsePrimary(depth + 1); if ("error" in child) return child; return { kind: "NOT", child }; }
    if (t.kind === "LPAREN") {
      next();
      const inner = parseOr(depth + 1);
      if ("error" in inner) return inner;
      if (peek()?.kind !== "RPAREN") return { error: "unbalanced parenthesis" };
      next();
      return inner;
    }
    if (t.kind === "WORD") {
      next();
      clauses++;
      if (clauses > DSL_LIMITS.maxClauses) return { error: `query exceeds ${DSL_LIMITS.maxClauses} clauses (§37/§126)` };
      const sugar = /^(after|before):(.+)$/i.exec(t.value!);
      if (sugar) {
        const node = parseDateSugar(sugar[1]!.toLowerCase(), sugar[2]!);
        return node ?? { error: `invalid date value: ${sugar[2]}` };
      }
      return parseWord(t.value!);
    }
    return { error: `unexpected token: ${t.kind}` };
  }

  function parseAnd(depth: number): DslNode | { error: string } {
    const first = parsePrimary(depth);
    if ("error" in first) return first;
    const children: DslNode[] = [first];
    for (;;) {
      const t = peek();
      if (t?.kind === "AND") { next(); const n = parsePrimary(depth); if ("error" in n) return n; children.push(n); continue; }
      // Implicit AND: another primary follows directly.
      if (t && (t.kind === "WORD" || t.kind === "LPAREN" || t.kind === "NOT")) {
        const n = parsePrimary(depth); if ("error" in n) return n; children.push(n); continue;
      }
      break;
    }
    return children.length === 1 ? children[0]! : { kind: "AND", children };
  }

  function parseOr(depth: number): DslNode | { error: string } {
    const first = parseAnd(depth);
    if ("error" in first) return first;
    const children: DslNode[] = [first];
    while (peek()?.kind === "OR") {
      next();
      const n = parseAnd(depth);
      if ("error" in n) return n;
      children.push(n);
    }
    return children.length === 1 ? children[0]! : { kind: "OR", children };
  }

  const ast = parseOr(0);
  if ("error" in ast) return { rejected: ast.error };
  if (pos !== toks.length) return { rejected: "trailing tokens after complete query" };
  return { ast, clauseCount: clauses };
}

/** A flat record the AST evaluates against (built by the service from tenant-scoped rows). */
export type DslRecord = Record<string, string | number | boolean | string[] | null | undefined> & { _text?: string; _time?: string };

function fieldValue(rec: DslRecord, field: string): string | number | boolean | string[] | null | undefined {
  return rec[field];
}

export function evaluateDsl(node: DslNode, rec: DslRecord): boolean {
  switch (node.kind) {
    case "AND": return node.children.every((c) => evaluateDsl(c, rec));
    case "OR": return node.children.some((c) => evaluateDsl(c, rec));
    case "NOT": return !evaluateDsl(node.child, rec);
    case "TERM": return (rec._text ?? "").toLowerCase().includes(node.value);
    case "DATE_RANGE": {
      const t = rec._time ? new Date(rec._time).getTime() : NaN;
      if (Number.isNaN(t)) return false;
      if (node.from && t < new Date(node.from).getTime()) return false;
      if (node.to && t > new Date(node.to).getTime()) return false;
      return true;
    }
    case "RANGE": {
      const v = fieldValue(rec, node.field);
      if (typeof v !== "number") return false;
      return node.op === "gte" ? v >= node.value : node.op === "lte" ? v <= node.value : node.op === "gt" ? v > node.value : v < node.value;
    }
    case "FIELD_FILTER": {
      const v = fieldValue(rec, node.field);
      if (v === null || v === undefined) return false;
      const norm = (x: unknown) => String(x).toLowerCase();
      if (node.op === "in") {
        const wanted = node.value as string[];
        if (Array.isArray(v)) return v.some((x) => wanted.includes(norm(x)));
        return wanted.includes(norm(v));
      }
      if (Array.isArray(v)) {
        const hit = v.some((x) => norm(x) === node.value);
        return node.op === "eq" ? hit : !hit;
      }
      const eq = typeof v === "boolean" ? String(v) === node.value : norm(v) === node.value;
      return node.op === "eq" ? eq : !eq;
    }
  }
}

/** Deterministic human-readable rendering of an AST (result explanations, §97). */
export function describeDsl(node: DslNode): string {
  switch (node.kind) {
    case "AND": return node.children.map(describeDsl).join(" AND ");
    case "OR": return `(${node.children.map(describeDsl).join(" OR ")})`;
    case "NOT": return `NOT ${describeDsl(node.child)}`;
    case "TERM": return `text contains "${node.value}"`;
    case "DATE_RANGE": return `date in [${node.from ?? "…"}, ${node.to ?? "…"}]`;
    case "RANGE": return `${node.field} ${node.op} ${node.value}`;
    case "FIELD_FILTER": return `${node.field} ${node.op === "in" ? "in" : "="} ${Array.isArray(node.value) ? node.value.join(",") : node.value}`;
  }
}

/** Field references that actually matched a record — deterministic "why this matched" (§97). */
export function matchedFields(node: DslNode, rec: DslRecord): string[] {
  const out: string[] = [];
  const walk = (n: DslNode): void => {
    if (n.kind === "AND" || n.kind === "OR") n.children.forEach(walk);
    else if (n.kind === "NOT") walk(n.child);
    else if (evaluateDsl(n, rec)) out.push(describeDsl(n));
  };
  walk(node);
  return out;
}
