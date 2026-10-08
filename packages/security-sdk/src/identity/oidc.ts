import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

/** OIDC Authorization Code Flow + PKCE validation (§48–52). All validation
 *  is strict: state, nonce, issuer, audience, RS256 signature against the
 *  provider JWKS, and expiration. Nothing about the IdP is trusted without
 *  a configured provider record + claims mapping. */

export function generatePkcePair(random: Buffer): { verifier: string; challenge: string; method: "S256" } {
  const verifier = random.toString("base64url");
  const challenge = createHash("sha256").update(verifier, "utf8").digest("base64url");
  return { verifier, challenge, method: "S256" };
}

export function verifyPkce(verifier: string, challenge: string): boolean {
  return createHash("sha256").update(verifier, "utf8").digest("base64url") === challenge;
}

export interface OidcDiscovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  userinfoEndpoint?: string;
}

export function validateDiscovery(doc: Record<string, unknown>, expectedIssuer: string): OidcDiscovery {
  const issuer = String(doc.issuer ?? "");
  if (issuer !== expectedIssuer) throw new Error(`OIDC discovery issuer mismatch: ${issuer}`);
  for (const field of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    const v = doc[field];
    if (typeof v !== "string" || !v.startsWith("https://")) throw new Error(`OIDC discovery missing/invalid ${field}`);
  }
  const responseTypes = doc.response_types_supported;
  if (Array.isArray(responseTypes) && !responseTypes.includes("code")) throw new Error("IdP does not support authorization code flow");
  return {
    issuer,
    authorizationEndpoint: String(doc.authorization_endpoint),
    tokenEndpoint: String(doc.token_endpoint),
    jwksUri: String(doc.jwks_uri),
    userinfoEndpoint: typeof doc.userinfo_endpoint === "string" ? doc.userinfo_endpoint : undefined,
  };
}

export interface Jwk { kty: string; kid?: string; n?: string; e?: string; x?: string; y?: string; crv?: string }

function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signingInput: string; signature: Buffer } {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed JWT");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as Record<string, unknown>;
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], "base64url") };
}

export interface OidcValidationInput {
  idToken: string;
  jwks: { keys: Jwk[] };
  expectedIssuer: string;
  expectedAudience: string; // client id
  expectedNonce: string;
  nowMs: number;
  clockSkewSeconds?: number;
}

/** Strict id_token validation (§51). Throws with a specific reason — the
 *  caller maps every failure to a generic SSO_LOGIN_FAILED audit + error. */
export function validateIdToken(input: OidcValidationInput): Record<string, unknown> {
  const { header, payload, signingInput, signature } = decodeJwt(input.idToken);
  if (header.alg !== "RS256") throw new Error(`Refusing id_token alg ${String(header.alg)}`);
  const jwk = input.jwks.keys.find((k) => k.kid === header.kid) ?? (input.jwks.keys.length === 1 ? input.jwks.keys[0] : undefined);
  if (!jwk) throw new Error("No matching JWKS key for id_token kid");
  const key = createPublicKey({ format: "jwk", key: jwk as never });
  if (!cryptoVerify("RSA-SHA256", Buffer.from(signingInput, "utf8"), key, signature)) throw new Error("id_token signature invalid");
  const skew = (input.clockSkewSeconds ?? 60) * 1000;
  const now = input.nowMs;
  if (payload.iss !== input.expectedIssuer) throw new Error("id_token issuer mismatch");
  const aud = payload.aud;
  const audOk = aud === input.expectedAudience || (Array.isArray(aud) && aud.includes(input.expectedAudience));
  if (!audOk) throw new Error("id_token audience mismatch");
  if (typeof payload.exp !== "number" || now > payload.exp * 1000 + skew) throw new Error("id_token expired");
  if (typeof payload.iat === "number" && payload.iat * 1000 > now + skew) throw new Error("id_token issued in the future");
  if (payload.nonce !== input.expectedNonce) throw new Error("id_token nonce mismatch");
  if (typeof payload.sub !== "string" || !payload.sub) throw new Error("id_token missing sub");
  return payload;
}

/** Map IdP claims to platform identity ONLY through configured claim names (§52). */
export function mapOidcClaims(claims: Record<string, unknown>, mapping: { emailClaim: string; nameClaim: string; groupsClaim: string; subjectClaim: string }): { email: string; displayName: string; groups: string[]; subject: string } {
  const email = claims[mapping.emailClaim];
  if (typeof email !== "string" || !email.includes("@")) throw new Error("Mapped email claim missing/invalid");
  const name = claims[mapping.nameClaim];
  const groupsRaw = claims[mapping.groupsClaim];
  const groups = Array.isArray(groupsRaw) ? groupsRaw.filter((g): g is string => typeof g === "string") : [];
  const subject = claims[mapping.subjectClaim] ?? claims.sub;
  return { email, displayName: typeof name === "string" ? name : email, groups, subject: String(subject ?? "") };
}
