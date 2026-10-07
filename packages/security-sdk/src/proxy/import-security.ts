/**
 * Import security (Prompt 8 §61–§62). Scanner exports and traffic files
 * are UNTRUSTED input — frequently attacker-influenced, since they describe
 * a target's responses. Every import path validates before parsing:
 *  - hard size caps (oversized payloads rejected, never truncated-parsed);
 *  - XML: DOCTYPE / ENTITY / external DTD constructs rejected outright
 *    (XXE against DSRclone itself is the attack being prevented), nesting
 *    depth capped, and the built-in parsers never resolve external refs;
 *  - JSON: parsed with a reviver-free JSON.parse after a size check;
 *  - archives are NOT accepted at all in this phase, which removes the
 *    zip-bomb class entirely (no zip extraction code exists here);
 *  - no value from an import is ever used as a filesystem path (artifact
 *    keys are platform-generated), removing path traversal by content.
 */

export const MAX_IMPORT_BYTES = 10 * 1024 * 1024; // 10 MiB hard cap per import (§62)
export const MAX_XML_DEPTH = 32;
export const MAX_IMPORT_RECORDS = 50_000;

export class ImportValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImportValidationError";
  }
}

export function assertImportSize(raw: string, maxBytes: number = MAX_IMPORT_BYTES): void {
  const bytes = Buffer.byteLength(raw, "utf8");
  if (bytes > maxBytes) {
    throw new ImportValidationError(`Import payload is ${bytes} bytes — exceeds the ${maxBytes}-byte cap (§62)`);
  }
  if (raw.includes("\u0000")) {
    throw new ImportValidationError("Import payload contains NUL bytes — rejected as malformed (§62)");
  }
}

/** Reject any XML document carrying DTD/entity machinery (§61). Scanner
 *  exports never need a DOCTYPE; its presence is treated as hostile. */
export function assertXmlSafe(xml: string): void {
  if (/<!DOCTYPE/i.test(xml)) throw new ImportValidationError("XML import rejected: DOCTYPE declarations are forbidden (XXE protection, §61)");
  if (/<!ENTITY/i.test(xml)) throw new ImportValidationError("XML import rejected: ENTITY declarations are forbidden (XXE protection, §61)");
  // Conditional sections (<![INCLUDE[…) are forbidden; CDATA is a plain
  // text container used by legitimate scanner exports and stays allowed.
  if (/<!\[(?!CDATA\[)/.test(xml)) throw new ImportValidationError("XML import rejected: conditional sections are forbidden (§61)");
  if (/\bSYSTEM\s+["']/i.test(xml) || /\bPUBLIC\s+["']/i.test(xml)) {
    throw new ImportValidationError("XML import rejected: external DTD references are forbidden (§61)");
  }
  // Nesting depth cap (§61): counted on raw tags — cheap and conservative.
  let depth = 0;
  let maxDepth = 0;
  for (const m of xml.matchAll(/<(\/?)([A-Za-z_][\w:.-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>/g)) {
    if (m[4] === "/") continue; // self-closing
    if (m[1] === "/") depth = Math.max(0, depth - 1);
    else { depth++; maxDepth = Math.max(maxDepth, depth); }
    if (maxDepth > MAX_XML_DEPTH) {
      throw new ImportValidationError(`XML import rejected: nesting exceeds ${MAX_XML_DEPTH} levels (§61)`);
    }
  }
}

/** Parse an import payload by declared format with all guards applied. */
export function parseImportJson(raw: string): unknown {
  assertImportSize(raw);
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new ImportValidationError("Import payload is not valid JSON (§62)");
  }
}

/**
 * Minimal safe XML reader for scanner exports (§61). Purpose-built for
 * record extraction (Burp issue exports): tokenizes tags/attributes/text,
 * decodes the five standard entities + numeric refs + CDATA, enforces the
 * depth cap, and — by construction — has no external-entity resolution,
 * no DTD processing and no filesystem/network access.
 */
export interface XmlNode {
  name: string;
  attributes: Record<string, string>;
  children: XmlNode[];
  /** Concatenated direct text content (entity-decoded). */
  text: string;
}

function decodeEntities(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}

export function parseXmlDocument(xml: string): XmlNode {
  assertImportSize(xml);
  assertXmlSafe(xml);
  const root: XmlNode = { name: "#root", attributes: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  const tokenRe = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<\?[\s\S]*?\?>|<(\/?)([A-Za-z_][\w:.-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>|[^<]+/g;
  let m: RegExpExecArray | null;
  while ((m = tokenRe.exec(xml)) !== null) {
    const tok = m[0];
    if (tok.startsWith("<!--") || tok.startsWith("<?")) continue;
    if (tok.startsWith("<![CDATA[")) {
      // CDATA is literal text — no entity decoding inside (§61-safe).
      stack[stack.length - 1]!.text += tok.slice(9, -3);
      continue;
    }
    if (m[2] === undefined) {
      // text node
      const parent = stack[stack.length - 1]!;
      parent.text += decodeEntities(tok);
      continue;
    }
    const name = m[2];
    if (m[1] === "/") {
      // closing tag: pop to the matching open element (tolerant of the
      // mildly malformed nesting real exports sometimes contain).
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i]!.name === name) { stack.length = i; break; }
      }
      continue;
    }
    const attrs: Record<string, string> = {};
    for (const am of (m[3] ?? "").matchAll(/([\w:.-]+)\s*=\s*"([^"]*)"|([\w:.-]+)\s*=\s*'([^']*)'/g)) {
      attrs[am[1] ?? am[3]!] = decodeEntities(am[2] ?? am[4] ?? "");
    }
    const node: XmlNode = { name, attributes: attrs, children: [], text: "" };
    stack[stack.length - 1]!.children.push(node);
    if (m[4] !== "/") {
      stack.push(node);
      if (stack.length > MAX_XML_DEPTH + 1) {
        throw new ImportValidationError(`XML import rejected: nesting exceeds ${MAX_XML_DEPTH} levels (§61)`);
      }
    }
  }
  const doc = root.children[0];
  if (!doc) throw new ImportValidationError("XML import contains no root element (§62)");
  return doc;
}

export function xmlChild(node: XmlNode, name: string): XmlNode | undefined {
  return node.children.find((c) => c.name === name);
}
export function xmlChildren(node: XmlNode, name: string): XmlNode[] {
  return node.children.filter((c) => c.name === name);
}
export function xmlText(node: XmlNode | undefined): string | undefined {
  if (!node) return undefined;
  const t = node.text.trim();
  return t.length > 0 ? t : undefined;
}
