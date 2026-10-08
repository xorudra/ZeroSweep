import { createHash, createPublicKey, createVerify, X509Certificate, type KeyObject } from "node:crypto";
// (createSign lives in saml-fixtures.ts, the test IdP.)

/** IdP signing material may be configured as a full X.509 certificate or a
 *  bare public key (both appear in real IdP metadata). Accept either. */
export function publicKeyFromIdpMaterial(pem: string): KeyObject {
  try {
    return new X509Certificate(pem).publicKey;
  } catch {
    return createPublicKey(pem);
  }
}

/** SAML 2.0 assertion validation (§53–56) with a hardened, dependency-free
 *  XML stack:
 *  - XXE is impossible by construction: any DOCTYPE / ENTITY / SYSTEM
 *    construct is rejected before parsing, and the parser has no entity
 *    expansion beyond the five predefined XML entities (§128).
 *  - Only enveloped XMLDSig with rsa-sha256 + sha256 digest + inclusive
 *    C14N is accepted; every other algorithm is refused.
 *  - Issuer, audience, destination/recipient, time validity and
 *    InResponseTo are all checked. Assertion IDs are returned so the
 *    caller can consume them for replay protection (§55).
 *  Encrypted assertions (§56) require an XML encryption stack; the config
 *  layer refuses providers that demand them (honest NOT_CONFIGURED). */

export class SamlRejected extends Error {}

/* ------------------------------ XXE guard -------------------------------- */
export function assertNoXxe(xml: string): void {
  const upper = xml.toUpperCase();
  if (upper.includes("<!DOCTYPE") || upper.includes("<!ENTITY") || upper.includes("<!SYSTEM") || upper.includes(" SYSTEM \"") || upper.includes(" SYSTEM '")) {
    throw new SamlRejected("DOCTYPE/ENTITY constructs are forbidden");
  }
}

/* --------------------------- minimal XML parser --------------------------- */
export interface XmlEl {
  name: string;
  attrs: Map<string, string>;
  children: XmlEl[];
  text: string;
}

const PREDEFINED_ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'" };

function decodeEntities(value: string): string {
  return value.replace(/&(#x?[0-9a-fA-F]+|\w+);/g, (whole, body: string) => {
    if (body.startsWith("#x") || body.startsWith("#X")) return String.fromCodePoint(parseInt(body.slice(2), 16));
    if (body.startsWith("#")) return String.fromCodePoint(parseInt(body.slice(1), 10));
    const resolved = PREDEFINED_ENTITIES[body];
    if (resolved === undefined) throw new SamlRejected(`Unknown entity &${body};`);
    return resolved;
  });
}

export function parseXml(xml: string): XmlEl {
  assertNoXxe(xml);
  if (xml.length > 1_000_000) throw new SamlRejected("XML document too large");
  let pos = 0;
  const stack: XmlEl[] = [];
  let root: XmlEl | null = null;
  const fail = (msg: string): never => { throw new SamlRejected(`XML parse error at ${pos}: ${msg}`); };
  while (pos < xml.length) {
    if (xml.startsWith("<?", pos)) {
      const end = xml.indexOf("?>", pos);
      if (end === -1) fail("unterminated processing instruction");
      pos = end + 2;
    } else if (xml.startsWith("<!--", pos)) {
      const end = xml.indexOf("-->", pos);
      if (end === -1) fail("unterminated comment");
      pos = end + 3;
    } else if (xml.startsWith("<![CDATA[", pos)) {
      const end = xml.indexOf("]]>", pos);
      if (end === -1) fail("unterminated CDATA");
      if (stack.length === 0) fail("CDATA outside root element");
      stack[stack.length - 1].text += xml.slice(pos + 9, end);
      pos = end + 3;
    } else if (xml.startsWith("</", pos)) {
      const end = xml.indexOf(">", pos);
      if (end === -1) fail("unterminated close tag");
      const name = xml.slice(pos + 2, end).trim();
      const el = stack.pop();
      if (!el || el.name !== name) fail(`mismatched close tag ${name}`);
      if (stack.length === 0 && el) { root = el; }
      pos = end + 1;
    } else if (xml[pos] === "<") {
      const end = xml.indexOf(">", pos);
      if (end === -1) fail("unterminated open tag");
      let inside = xml.slice(pos + 1, end);
      const selfClosing = inside.endsWith("/");
      if (selfClosing) inside = inside.slice(0, -1);
      const nameMatch = /^([^\s/>]+)/.exec(inside);
      if (!nameMatch) fail("missing element name");
      const el: XmlEl = { name: nameMatch![1], attrs: new Map(), children: [], text: "" };
      const attrSrc = inside.slice(nameMatch![1].length);
      const attrRe = /([^\s=/>]+)\s*=\s*"([^"]*)"|([^\s=/>]+)\s*=\s*'([^']*)'/g;
      let m: RegExpExecArray | null;
      while ((m = attrRe.exec(attrSrc)) !== null) {
        const attrName = m[1] ?? m[3];
        const attrValue = m[2] ?? m[4];
        el.attrs.set(attrName, decodeEntities(attrValue));
      }
      if (stack.length > 0) stack[stack.length - 1].children.push(el);
      else if (root) fail("multiple root elements");
      else if (selfClosing) root = el;
      if (!selfClosing) stack.push(el);
      pos = end + 1;
    } else {
      const next = xml.indexOf("<", pos);
      const raw = xml.slice(pos, next === -1 ? xml.length : next);
      if (stack.length > 0) stack[stack.length - 1].text += decodeEntities(raw);
      else if (raw.trim()) fail("text outside root element");
      pos = next === -1 ? xml.length : next;
    }
  }
  if (stack.length !== 0) fail("unclosed elements remain");
  if (!root) fail("no root element");
  return root as XmlEl;
}

export function findChild(el: XmlEl, localName: string): XmlEl | undefined {
  return el.children.find((c) => localOf(c.name) === localName);
}
export function findChildren(el: XmlEl, localName: string): XmlEl[] {
  return el.children.filter((c) => localOf(c.name) === localName);
}
export function findDescendant(el: XmlEl, localName: string): XmlEl | undefined {
  if (localOf(el.name) === localName) return el;
  for (const child of el.children) {
    const found = findDescendant(child, localName);
    if (found) return found;
  }
  return undefined;
}
export function localOf(qname: string): string {
  const idx = qname.indexOf(":");
  return idx === -1 ? qname : qname.slice(idx + 1);
}
export function prefixOf(qname: string): string | null {
  const idx = qname.indexOf(":");
  return idx === -1 ? null : qname.slice(0, idx);
}

/* ------------------------- inclusive C14N subset -------------------------- */
function escapeText(t: string): string {
  return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\r/g, "&#xD;");
}
function escapeAttr(v: string): string {
  return v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;")
    .replace(/\t/g, "&#x9;").replace(/\n/g, "&#xA;").replace(/\r/g, "&#xD;");
}

function nsDeclarationsOf(el: XmlEl): Map<string, string> {
  const decls = new Map<string, string>();
  for (const [name, value] of el.attrs) {
    if (name === "xmlns") decls.set("", value);
    else if (name.startsWith("xmlns:")) decls.set(name.slice(6), value);
  }
  return decls;
}

export function canonicalize(el: XmlEl, ancestorNs: Map<string, string>, excludeLocalName?: string): string {
  const inScope = new Map(ancestorNs);
  for (const [p, uri] of nsDeclarationsOf(el)) inScope.set(p, uri);
  return renderCanonical(el, inScope, new Map(), excludeLocalName);
}

function renderCanonical(el: XmlEl, inScope: Map<string, string>, rendered: Map<string, string>, excludeLocalName?: string): string {
  const toRender = new Map<string, string>();
  for (const [prefix, uri] of inScope) {
    if (rendered.get(prefix) !== uri) toRender.set(prefix, uri);
  }
  const childRendered = new Map(rendered);
  for (const [p, uri] of toRender) childRendered.set(p, uri);
  let out = `<${el.name}`;
  const nsSorted = [...toRender.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  for (const [prefix, uri] of nsSorted) out += prefix === "" ? ` xmlns="${escapeAttr(uri)}"` : ` xmlns:${prefix}="${escapeAttr(uri)}"`;
  const plainAttrs: [string, string][] = [];
  const nsAttrs: [string, string, string][] = [];
  for (const [name, value] of el.attrs) {
    if (name === "xmlns" || name.startsWith("xmlns:")) continue;
    const prefix = prefixOf(name);
    if (prefix && prefix !== "xml") nsAttrs.push([inScope.get(prefix) ?? "", localOf(name), `${name}="${escapeAttr(value)}"`]);
    else plainAttrs.push([name, `${name}="${escapeAttr(value)}"`]);
  }
  plainAttrs.sort((a, b) => (a[0] < b[0] ? -1 : 1));
  nsAttrs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : a[0] < b[0] ? -1 : 1));
  for (const [, renderedAttr] of plainAttrs) out += ` ${renderedAttr}`;
  for (const [, , renderedAttr] of nsAttrs) out += ` ${renderedAttr}`;
  out += ">";
  out += escapeText(el.text);
  for (const child of el.children) {
    if (excludeLocalName && localOf(child.name) === excludeLocalName) continue;
    const childScope = new Map(inScope);
    for (const [p, uri] of nsDeclarationsOf(child)) childScope.set(p, uri);
    out += renderCanonical(child, childScope, childRendered, excludeLocalName);
  }
  out += `</${el.name}>`;
  return out;
}

/** Collect in-scope namespace declarations from root down to `target`. */
export function ancestorNamespaces(root: XmlEl, target: XmlEl): Map<string, string> {
  const path: XmlEl[] = [];
  const walk = (el: XmlEl): boolean => {
    path.push(el);
    if (el === target) return true;
    for (const child of el.children) if (walk(child)) return true;
    path.pop();
    return false;
  };
  walk(root);
  const ns = new Map<string, string>();
  for (const el of path.slice(0, -1)) for (const [p, uri] of nsDeclarationsOf(el)) ns.set(p, uri);
  return ns;
}

/* --------------------------- assertion checks ----------------------------- */
export interface SamlValidationInput {
  responseXml: string;
  idpEntityId: string;
  idpCertificatePem: string;
  spEntityId: string;
  acsUrl: string;
  expectedInResponseTo?: string | null;
  nowMs: number;
  clockSkewSeconds?: number;
}

export interface SamlIdentity {
  assertionId: string;
  nameId: string;
  attributes: Record<string, string[]>;
}

export function validateSamlResponse(input: SamlValidationInput): SamlIdentity {
  const root = parseXml(input.responseXml);
  if (localOf(root.name) !== "Response") throw new SamlRejected("Root element is not a SAML Response");
  const assertion = findChild(root, "Assertion") ?? findDescendant(root, "Assertion");
  if (!assertion) throw new SamlRejected("No Assertion present");
  const signature = findChild(assertion, "Signature");
  if (!signature) throw new SamlRejected("Assertion is not signed — refused (§143)");

  const signedInfo = findChild(signature, "SignedInfo");
  const signatureValueEl = findChild(signature, "SignatureValue");
  if (!signedInfo || !signatureValueEl) throw new SamlRejected("Signature is incomplete");
  const c14nMethod = findChild(signedInfo, "CanonicalizationMethod")?.attrs.get("Algorithm") ?? "";
  if (!c14nMethod.includes("REC-xml-c14n-20010315")) throw new SamlRejected(`Unsupported canonicalization ${c14nMethod}`);
  const sigMethod = findChild(signedInfo, "SignatureMethod")?.attrs.get("Algorithm") ?? "";
  if (!sigMethod.endsWith("rsa-sha256")) throw new SamlRejected(`Unsupported signature method ${sigMethod}`);
  const reference = findChild(signedInfo, "Reference");
  if (!reference) throw new SamlRejected("SignedInfo has no Reference");
  const assertionId = assertion.attrs.get("ID");
  if (!assertionId || reference.attrs.get("URI") !== `#${assertionId}`) throw new SamlRejected("Reference URI does not identify the Assertion");
  const transforms = findChildren(findChild(reference, "Transforms") ?? ({ children: [] } as unknown as XmlEl), "Transform").map((t) => t.attrs.get("Algorithm") ?? "");
  const hasEnveloped = transforms.some((t) => t.endsWith("enveloped-signature"));
  const hasC14n = transforms.some((t) => t.includes("REC-xml-c14n-20010315"));
  if (!hasEnveloped || !hasC14n) throw new SamlRejected("Reference transforms must be enveloped-signature + C14N");
  const digestMethod = findChild(reference, "DigestMethod")?.attrs.get("Algorithm") ?? "";
  if (!digestMethod.endsWith("sha256")) throw new SamlRejected("Digest method must be sha256");
  const digestValue = findChild(reference, "DigestValue")?.text.trim() ?? "";

  const assertionNs = ancestorNamespaces(root, assertion);
  const canonicalAssertion = canonicalize(assertion, assertionNs, "Signature");
  const computedDigest = createHash("sha256").update(canonicalAssertion, "utf8").digest("base64");
  if (computedDigest !== digestValue) throw new SamlRejected("Assertion digest mismatch");

  const signedInfoNs = ancestorNamespaces(root, signedInfo);
  // In-scope namespaces for SignedInfo include those declared on Signature.
  for (const [p, uri] of nsDeclarationsOf(signature)) if (!signedInfoNs.has(p)) signedInfoNs.set(p, uri);
  const canonicalSignedInfo = canonicalize(signedInfo, signedInfoNs);
  const idpKey = publicKeyFromIdpMaterial(input.idpCertificatePem);
  const verifier = createVerify("RSA-SHA256");
  verifier.update(canonicalSignedInfo, "utf8");
  const signatureOk = verifier.verify(idpKey, Buffer.from(signatureValueEl.text.trim(), "base64"));
  if (!signatureOk) throw new SamlRejected("Assertion signature invalid");

  const issuer = findChild(assertion, "Issuer")?.text.trim();
  if (issuer !== input.idpEntityId) throw new SamlRejected("Assertion issuer mismatch");
  const skewMs = (input.clockSkewSeconds ?? 120) * 1000;
  const conditions = findChild(assertion, "Conditions");
  if (!conditions) throw new SamlRejected("Assertion has no Conditions");
  const notBefore = conditions.attrs.get("NotBefore");
  const notOnOrAfter = conditions.attrs.get("NotOnOrAfter");
  if (notBefore && input.nowMs < Date.parse(notBefore) - skewMs) throw new SamlRejected("Assertion not yet valid");
  if (notOnOrAfter && input.nowMs >= Date.parse(notOnOrAfter) + skewMs) throw new SamlRejected("Assertion expired");
  const audiences = findChildren(conditions, "AudienceRestriction").flatMap((ar) => findChildren(ar, "Audience").map((a) => a.text.trim()));
  if (!audiences.includes(input.spEntityId)) throw new SamlRejected("Assertion audience does not include this SP");

  const subject = findChild(assertion, "Subject");
  const nameId = findChild(subject ?? assertion, "NameID")?.text.trim();
  if (!nameId) throw new SamlRejected("Assertion has no NameID");
  const confirmationData = subject ? findDescendant(subject, "SubjectConfirmationData") : undefined;
  if (confirmationData) {
    const recipient = confirmationData.attrs.get("Recipient");
    if (recipient && recipient !== input.acsUrl) throw new SamlRejected("Assertion recipient/destination mismatch");
    if (input.expectedInResponseTo && confirmationData.attrs.get("InResponseTo") !== input.expectedInResponseTo) {
      throw new SamlRejected("Assertion InResponseTo mismatch");
    }
    const scNotOnOrAfter = confirmationData.attrs.get("NotOnOrAfter");
    if (scNotOnOrAfter && input.nowMs >= Date.parse(scNotOnOrAfter) + skewMs) throw new SamlRejected("Subject confirmation expired");
  }

  const attributes: Record<string, string[]> = {};
  const attrStatement = findChild(assertion, "AttributeStatement");
  if (attrStatement) {
    for (const attr of findChildren(attrStatement, "Attribute")) {
      const name = attr.attrs.get("Name");
      if (!name) continue;
      attributes[name] = findChildren(attr, "AttributeValue").map((v) => v.text.trim());
    }
  }
  return { assertionId, nameId, attributes };
}

/** Map assertion attributes to identity ONLY via configured attribute names (§53). */
export function mapSamlAttributes(identity: SamlIdentity, mapping: { emailAttribute: string; nameAttribute: string; groupsAttribute: string }): { email: string; displayName: string; groups: string[] } {
  const email = identity.attributes[mapping.emailAttribute]?.[0] ?? (identity.nameId.includes("@") ? identity.nameId : undefined);
  if (!email) throw new SamlRejected("Mapped email attribute missing");
  return {
    email,
    displayName: identity.attributes[mapping.nameAttribute]?.[0] ?? email,
    groups: identity.attributes[mapping.groupsAttribute] ?? [],
  };
}
