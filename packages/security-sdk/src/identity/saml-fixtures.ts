import { createHash, createSign } from "node:crypto";
import { ancestorNamespaces, canonicalize, findChild, findDescendant, parseXml } from "./saml";

/** Fixture SAML IdP (test-only): mints Response documents signed with a
 *  test key, using the same canonicalizer the verifier enforces — so valid
 *  fixtures pass and any post-signing tamper, wrong key, wrong audience or
 *  expiry fails for the same reasons a real IdP's would. No live IdP is
 *  contacted anywhere in this phase. */

export interface SamlFixtureOptions {
  idpEntityId: string;
  spEntityId: string;
  acsUrl: string;
  inResponseTo?: string;
  nameId: string;
  attributes?: Record<string, string[]>;
  assertionId?: string;
  nowMs: number;
  notBeforeOffsetMs?: number;
  notOnOrAfterOffsetMs?: number;
  privateKeyPem: string;
}

const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";
const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

function iso(ms: number): string { return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z"); }
function esc(s: string): string { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

export function buildUnsignedResponse(o: SamlFixtureOptions): string {
  const assertionId = o.assertionId ?? "_fixtureAssertion1";
  const issueInstant = iso(o.nowMs);
  const notBefore = iso(o.nowMs + (o.notBeforeOffsetMs ?? -60_000));
  const notOnOrAfter = iso(o.nowMs + (o.notOnOrAfterOffsetMs ?? 5 * 60_000));
  const attrs = Object.entries(o.attributes ?? { email: [o.nameId], displayName: ["Rudra"], groups: [] })
    .map(([name, values]) => `<saml:Attribute Name="${esc(name)}">${values.map((v) => `<saml:AttributeValue>${esc(v)}</saml:AttributeValue>`).join("")}</saml:Attribute>`)
    .join("");
  return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="${SAML_NS}" xmlns:ds="${DS_NS}" ID="_response1" Version="2.0" IssueInstant="${issueInstant}" Destination="${esc(o.acsUrl)}"${o.inResponseTo ? ` InResponseTo="${esc(o.inResponseTo)}"` : ""}>`
    + `<saml:Issuer>${esc(o.idpEntityId)}</saml:Issuer>`
    + `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`
    + `<saml:Assertion ID="${esc(assertionId)}" Version="2.0" IssueInstant="${issueInstant}">`
    + `<saml:Issuer>${esc(o.idpEntityId)}</saml:Issuer>`
    + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${esc(o.nameId)}</saml:NameID>`
    + `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="${esc(o.acsUrl)}" NotOnOrAfter="${notOnOrAfter}"${o.inResponseTo ? ` InResponseTo="${esc(o.inResponseTo)}"` : ""}/></saml:SubjectConfirmation></saml:Subject>`
    + `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${esc(o.spEntityId)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AuthnStatement AuthnInstant="${issueInstant}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + `<saml:AttributeStatement>${attrs}</saml:AttributeStatement>`
    + `</saml:Assertion></samlp:Response>`;
}

export function signResponse(unsignedXml: string, privateKeyPem: string): string {
  const root = parseXml(unsignedXml);
  const assertion = findChild(root, "Assertion") ?? findDescendant(root, "Assertion");
  if (!assertion) throw new Error("fixture: no assertion");
  const digest = createHash("sha256").update(canonicalize(assertion, ancestorNamespaces(root, assertion)), "utf8").digest("base64");
  const assertionId = assertion.attrs.get("ID");
  const signedInfo = `<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="${C14N}"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#${assertionId}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="${C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>`;
  const signatureSkeleton = `<ds:Signature>${signedInfo}<ds:SignatureValue></ds:SignatureValue></ds:Signature>`;
  const issuerClose = "</saml:Issuer>";
  const idx = unsignedXml.indexOf(issuerClose, unsignedXml.indexOf("<saml:Assertion")) + issuerClose.length;
  const withSignature = unsignedXml.slice(0, idx) + signatureSkeleton + unsignedXml.slice(idx);
  // Compute the signature over the canonicalized SignedInfo in the final tree.
  const root2 = parseXml(withSignature);
  const assertion2 = findChild(root2, "Assertion") ?? findDescendant(root2, "Assertion");
  if (!assertion2) throw new Error("fixture: no assertion after insert");
  const signatureEl = findChild(assertion2, "Signature");
  if (!signatureEl) throw new Error("fixture: no signature element");
  const signedInfoEl = findChild(signatureEl, "SignedInfo");
  if (!signedInfoEl) throw new Error("fixture: no SignedInfo");
  const ns = ancestorNamespaces(root2, signedInfoEl);
  // Mirror the validator: ancestor namespaces + any declared on Signature.
  for (const [name, value] of signatureEl.attrs) {
    if (name === "xmlns") ns.set("", value);
    else if (name.startsWith("xmlns:")) ns.set(name.slice(6), value);
  }
  const canonicalSignedInfo = canonicalize(signedInfoEl, ns);
  const signer = createSign("RSA-SHA256");
  signer.update(canonicalSignedInfo, "utf8");
  const signatureValue = signer.sign(privateKeyPem, "base64");
  return withSignature.replace("<ds:SignatureValue></ds:SignatureValue>", `<ds:SignatureValue>${signatureValue}</ds:SignatureValue>`);
}

export function buildSignedResponse(o: SamlFixtureOptions): string {
  return signResponse(buildUnsignedResponse(o), o.privateKeyPem);
}
