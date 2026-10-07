/**
 * Minimal hardened XML reader for scanner output (Prompt 10 §16).
 *
 * Scanner XML is HOSTILE input. This reader is a small purpose-built
 * tokenizer for machine-generated tool output (Nmap / arp-scan), NOT a
 * general XML parser:
 * - DOCTYPE and ENTITY declarations are REJECTED outright (no XXE, no
 *   DTD loading, no entity expansion — only the five predefined XML
 *   entities are decoded).
 * - Input size, element depth and node count are hard-capped.
 * - Malformed input returns an error, never a partial tree the caller
 *   might trust.
 */

export interface XmlNode {
  tag: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  text: string;
}

export const MAX_XML_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 64;
const MAX_NODES = 200000;

const ENTITY_DECODE: Record<string, string> = {
  "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": "\"", "&apos;": "'",
};

function decodeEntities(s: string): string {
  return s.replace(/&(amp|lt|gt|quot|apos);/g, (m) => ENTITY_DECODE[m] ?? m)
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex: string) => {
      const code = parseInt(hex, 16);
      return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
    })
    .replace(/&#(\d+);/g, (_, dec: string) => {
      const code = parseInt(dec, 10);
      return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
    });
}

export function parseXmlLite(raw: string): { root: XmlNode } | { error: string } {
  if (raw.length > MAX_XML_BYTES) return { error: `input exceeds ${MAX_XML_BYTES} bytes` };
  // §16: external entities and DTDs are never processed. ENTITY
  // declarations and DOCTYPEs carrying an internal subset or an
  // external (SYSTEM/PUBLIC) reference are rejected outright. A BARE
  // <!DOCTYPE name> (which real Nmap output carries) declares nothing
  // and is skipped by the tokenizer below.
  if (/<!ENTITY/i.test(raw) || /<!DOCTYPE[^>]*(?:\[|\bSYSTEM\b|\bPUBLIC\b)/i.test(raw)) {
    return { error: "DOCTYPE with DTD subset/external reference and ENTITY declarations are forbidden in scanner output" };
  }
  const root: XmlNode = { tag: "#root", attrs: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  let nodes = 0;
  let i = 0;
  const len = raw.length;
  while (i < len) {
    const lt = raw.indexOf("<", i);
    if (lt === -1) {
      stack[stack.length - 1]!.text += decodeEntities(raw.slice(i));
      break;
    }
    if (lt > i) stack[stack.length - 1]!.text += decodeEntities(raw.slice(i, lt));
    if (raw.startsWith("<!--", lt)) {
      const end = raw.indexOf("-->", lt + 4);
      if (end === -1) return { error: "unterminated comment" };
      i = end + 3;
      continue;
    }
    if (raw.startsWith("<![CDATA[", lt)) {
      const end = raw.indexOf("]]>", lt + 9);
      if (end === -1) return { error: "unterminated CDATA" };
      stack[stack.length - 1]!.text += raw.slice(lt + 9, end);
      i = end + 3;
      continue;
    }
    if (raw.startsWith("<?", lt)) {
      const end = raw.indexOf("?>", lt + 2);
      if (end === -1) return { error: "unterminated processing instruction" };
      i = end + 2;
      continue;
    }
    if (/^<!DOCTYPE/i.test(raw.slice(lt, lt + 9))) {
      const end = raw.indexOf(">", lt);
      if (end === -1) return { error: "unterminated DOCTYPE" };
      i = end + 1;
      continue;
    }
    const gt = raw.indexOf(">", lt);
    if (gt === -1) return { error: "unterminated tag" };
    const inner = raw.slice(lt + 1, gt);
    if (inner.startsWith("/")) {
      const tag = inner.slice(1).trim().toLowerCase();
      if (stack.length <= 1) return { error: `unexpected closing tag </${tag}>` };
      const node = stack.pop()!;
      if (node.tag !== tag) return { error: `mismatched closing tag </${tag}> for <${node.tag}>` };
      i = gt + 1;
      continue;
    }
    const selfClose = inner.endsWith("/");
    const body = selfClose ? inner.slice(0, -1) : inner;
    const spaceIdx = body.search(/\s/);
    const tag = (spaceIdx === -1 ? body : body.slice(0, spaceIdx)).trim().toLowerCase();
    if (!/^[a-z][a-z0-9_.:-]*$/.test(tag)) return { error: `invalid tag name "${tag.slice(0, 40)}"` };
    const attrs: Record<string, string> = {};
    const attrSrc = spaceIdx === -1 ? "" : body.slice(spaceIdx + 1);
    const attrRe = /([a-zA-Z0-9_.:-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
    let m: RegExpExecArray | null;
    while ((m = attrRe.exec(attrSrc)) !== null) {
      attrs[m[1]!.toLowerCase()] = decodeEntities(m[3] ?? m[4] ?? "");
    }
    const node: XmlNode = { tag, attrs, children: [], text: "" };
    if (++nodes > MAX_NODES) return { error: "node count exceeds cap" };
    stack[stack.length - 1]!.children.push(node);
    if (!selfClose) {
      stack.push(node);
      if (stack.length > MAX_DEPTH) return { error: "element nesting exceeds cap" };
    }
    i = gt + 1;
  }
  if (stack.length !== 1) return { error: "unclosed elements at end of input" };
  const first = root.children[0];
  if (!first) return { error: "no root element" };
  return { root: first };
}

export function childrenNamed(node: XmlNode, tag: string): XmlNode[] {
  return node.children.filter((c) => c.tag === tag);
}

export function firstChild(node: XmlNode, tag: string): XmlNode | undefined {
  return node.children.find((c) => c.tag === tag);
}
