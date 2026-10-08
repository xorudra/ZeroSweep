/** SCIM 2.0 filter subset (§72): a strict recursive-descent parser producing
 *  a typed AST, evaluated in memory against records. Untrusted filters are
 *  NEVER translated to raw SQL. Only allowlisted attributes and operators
 *  are supported; anything else is rejected. */

export type ScimFilter =
  | { kind: "compare"; attr: string; op: "eq" | "ne" | "co" | "sw" | "ew" | "gt" | "lt" | "ge" | "le"; value: string }
  | { kind: "present"; attr: string }
  | { kind: "and" | "or"; left: ScimFilter; right: ScimFilter }
  | { kind: "not"; inner: ScimFilter };

const ALLOWED_ATTRS = new Set([
  "userName", "displayName", "name.familyName", "name.givenName", "active",
  "emails.value", "externalId", "title", "groups.value", "id",
]);
const OPS = new Set(["eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le", "pr"]);

export class ScimFilterError extends Error {}

export function parseScimFilter(input: string): ScimFilter {
  if (input.length > 500) throw new ScimFilterError("Filter too long");
  if (/[';]|--|\/\*|\bunion\b|\bselect\b/i.test(input.replace(/"[^"]*"/g, ""))) {
    // Quotes are stripped first so legitimate string values aren't blocked;
    // SQL-shaped tokens outside strings are rejected outright.
    throw new ScimFilterError("Filter contains forbidden tokens");
  }
  let pos = 0;
  const skipWs = () => { while (input[pos] === " ") pos++; };
  const peekWord = (): string => {
    skipWs();
    const m = /^[A-Za-z][A-Za-z0-9.]*/.exec(input.slice(pos));
    return m ? m[0] : "";
  };
  function parseOr(): ScimFilter {
    let left = parseAnd();
    while (peekWord().toLowerCase() === "or") { pos += peekWord().length; left = { kind: "or", left, right: parseAnd() }; }
    return left;
  }
  function parseAnd(): ScimFilter {
    let left = parseUnary();
    while (peekWord().toLowerCase() === "and") { pos += peekWord().length; left = { kind: "and", left, right: parseUnary() }; }
    return left;
  }
  function parseUnary(): ScimFilter {
    skipWs();
    if (peekWord().toLowerCase() === "not") {
      pos += 3;
      skipWs();
      if (input[pos] !== "(") throw new ScimFilterError("not must be followed by (");
      pos++;
      const inner = parseOr();
      skipWs();
      if (input[pos] !== ")") throw new ScimFilterError("expected )");
      pos++;
      return { kind: "not", inner };
    }
    if (input[pos] === "(") {
      pos++;
      const inner = parseOr();
      skipWs();
      if (input[pos] !== ")") throw new ScimFilterError("expected )");
      pos++;
      return inner;
    }
    return parseComparison();
  }
  function parseComparison(): ScimFilter {
    skipWs();
    const attrMatch = /^[A-Za-z][A-Za-z0-9.]*/.exec(input.slice(pos));
    if (!attrMatch) throw new ScimFilterError("expected attribute");
    const attr = attrMatch[0];
    if (!ALLOWED_ATTRS.has(attr)) throw new ScimFilterError(`attribute ${attr} is not filterable`);
    pos += attr.length;
    skipWs();
    const opMatch = /^[a-z]{2}/.exec(input.slice(pos));
    if (!opMatch || !OPS.has(opMatch[0])) throw new ScimFilterError("expected operator");
    const op = opMatch[0];
    pos += 2;
    if (op === "pr") return { kind: "present", attr };
    skipWs();
    if (input[pos] !== "\"") throw new ScimFilterError("expected quoted value");
    const end = input.indexOf("\"", pos + 1);
    if (end === -1) throw new ScimFilterError("unterminated string value");
    const value = input.slice(pos + 1, end);
    pos = end + 1;
    return { kind: "compare", attr, op: op as never, value };
  }
  const result = parseOr();
  skipWs();
  if (pos !== input.length) throw new ScimFilterError("trailing characters in filter");
  return result;
}

function attrValue(record: Record<string, unknown>, attr: string): unknown {
  if (attr === "emails.value") {
    const emails = record.emails;
    if (Array.isArray(emails)) return (emails[0] as { value?: unknown })?.value;
    return record.email;
  }
  if (attr === "groups.value") return record.groupIds;
  if (attr === "name.familyName") return (record.name as { familyName?: unknown })?.familyName ?? record.familyName;
  if (attr === "name.givenName") return (record.name as { givenName?: unknown })?.givenName ?? record.givenName;
  return record[attr];
}

export function evaluateScimFilter(filter: ScimFilter, record: Record<string, unknown>): boolean {
  switch (filter.kind) {
    case "and": return evaluateScimFilter(filter.left, record) && evaluateScimFilter(filter.right, record);
    case "or": return evaluateScimFilter(filter.left, record) || evaluateScimFilter(filter.right, record);
    case "not": return !evaluateScimFilter(filter.inner, record);
    case "present": {
      const v = attrValue(record, filter.attr);
      return v !== undefined && v !== null && v !== "";
    }
    case "compare": {
      const raw = attrValue(record, filter.attr);
      if (Array.isArray(raw)) return raw.some((v) => compareOne(v, filter.op, filter.value));
      return compareOne(raw, filter.op, filter.value);
    }
  }
}

function compareOne(raw: unknown, op: string, value: string): boolean {
  if (raw === undefined || raw === null) return op === "ne";
  if (typeof raw === "boolean") {
    const expected = value.toLowerCase() === "true";
    return op === "eq" ? raw === expected : op === "ne" ? raw !== expected : false;
  }
  const s = String(raw);
  switch (op) {
    case "eq": return s.toLowerCase() === value.toLowerCase();
    case "ne": return s.toLowerCase() !== value.toLowerCase();
    case "co": return s.toLowerCase().includes(value.toLowerCase());
    case "sw": return s.toLowerCase().startsWith(value.toLowerCase());
    case "ew": return s.toLowerCase().endsWith(value.toLowerCase());
    case "gt": return s > value;
    case "lt": return s < value;
    case "ge": return s >= value;
    case "le": return s <= value;
    default: return false;
  }
}
