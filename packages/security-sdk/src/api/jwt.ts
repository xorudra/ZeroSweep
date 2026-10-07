import { createHash } from "node:crypto";
import type { NormalizedJwtProfile } from "../findings/finding.types";
import { owaspApiCategoryFor } from "./taxonomy";

/**
 * JWT inspection (Prompt 9 §22–§25, §65, §70). INSPECTION ONLY:
 *  - tokens are decoded and their configuration analysed;
 *  - there is NO signature cracking, NO algorithm-confusion attack, NO
 *    tampering — those capabilities do not exist in this codebase (§79);
 *  - the raw token is never stored, logged or returned: records carry a
 *    sha256 fingerprint + header + REDACTED claims (§25/§65).
 */

export const JWT_MAX_TOKEN_BYTES = 8_192;
export const JWT_MAX_CLAIMS = 100;

const STRONG_ASYMMETRIC_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"];
const SYMMETRIC_ALGS = ["HS256", "HS384", "HS512"];
const KNOWN_WEAK_ALGS = ["none", "None", "NONE", ""];

const SENSITIVE_CLAIM_KEYS = [
  "password", "passwd", "secret", "api_key", "apikey", "api-key", "access_key", "private_key",
  "ssn", "social_security", "credit_card", "creditcard", "card_number", "cvv", "pin",
  "date_of_birth", "dob", "passport", "driver_license", "bank_account", "iban",
];

export interface JwtPolicyExpectations {
  /** Policy expects tokens to expire (§24). Default true. */
  requireExpiry?: boolean;
  /** Maximum acceptable lifetime in seconds. Default 24h. */
  maxLifetimeSeconds?: number;
  /** When configured, issuer/audience consistency is checked (§24). */
  expectedIssuer?: string;
  expectedAudience?: string;
  /** When true, a symmetric (HS*) algorithm is a policy finding —
   *  public APIs verifying with a shared secret is a weak indicator. */
  asymmetricExpected?: boolean;
}

export interface JwtCheckFinding {
  vulnClass: string;
  severity: "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  title: string;
  description: string;
  confidence: number;
  owaspCategory?: string;
}

export interface JwtInspection {
  profile: NormalizedJwtProfile;
  findings: JwtCheckFinding[];
  /** Non-finding observations (design choices that are NOT labelled
   *  vulnerabilities, §24). */
  observations: string[];
}

export class JwtInspectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JwtInspectionError";
  }
}

function base64UrlDecode(segment: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new JwtInspectionError("token segment is not valid base64url");
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function parseJsonObject(text: string, what: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new JwtInspectionError(`token ${what} is not valid JSON`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new JwtInspectionError(`token ${what} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

function jsonDepth(value: unknown, depth = 0): number {
  if (depth > 10) return depth;
  if (Array.isArray(value)) return Math.max(depth, ...value.map((v) => jsonDepth(v, depth + 1)));
  if (typeof value === "object" && value !== null) return Math.max(depth, ...Object.values(value).map((v) => jsonDepth(v, depth + 1)));
  return depth;
}

export function jwtFingerprint(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

const REDACTED = "REDACTED";

/** Redacted claim value for display (§25): sensitive keys are fully
 *  redacted; identifiers are truncated to a short prefix; small scalar
 *  policy values (scope/roles/iss/aud) stay readable because they are
 *  configuration, not secrets. */
export function redactClaimValue(key: string, value: unknown): unknown {
  const k = key.toLowerCase();
  if (SENSITIVE_CLAIM_KEYS.some((s) => k.includes(s))) return REDACTED;
  if (k === "sub" || k === "jti" || k === "email" || k === "phone" || k === "name" || k === "preferred_username") {
    if (typeof value === "string" && value.length > 0) return `${value.slice(0, 3)}…${REDACTED}`;
    return REDACTED;
  }
  if (typeof value === "string" && value.length > 64) return `${value.slice(0, 16)}…`;
  if (Array.isArray(value)) return value.slice(0, 10).map((v) => (typeof v === "string" && v.length > 64 ? `${v.slice(0, 16)}…` : v));
  return value;
}

function isoFromEpochSeconds(v: unknown): string | undefined {
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) return undefined;
  const d = new Date(v * 1000);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/**
 * Inspect one explicitly provided/captured authorized test token (§22).
 * The caller owns the token's lifecycle: it arrives in memory, is
 * analysed, and only the fingerprint/metadata record leaves this
 * function. Signature verification is deliberately NOT performed —
 * inspection is configuration analysis, not authentication (§24).
 */
export function inspectJwt(token: string, opts: { source: string; host?: string; endpoint?: string; policy?: JwtPolicyExpectations }): JwtInspection {
  if (typeof token !== "string" || token.length === 0) throw new JwtInspectionError("token is empty");
  if (Buffer.byteLength(token) > JWT_MAX_TOKEN_BYTES) throw new JwtInspectionError(`token exceeds ${JWT_MAX_TOKEN_BYTES} bytes`);
  const parts = token.split(".");
  if (parts.length !== 3) throw new JwtInspectionError("token is not a compact JWT (expected 3 segments)");
  const header = parseJsonObject(base64UrlDecode(parts[0]!), "header");
  const payload = parseJsonObject(base64UrlDecode(parts[1]!), "payload");
  if (jsonDepth(payload) > 8) throw new JwtInspectionError("token payload is too deeply nested");
  const claimKeys = Object.keys(payload);
  if (claimKeys.length > JWT_MAX_CLAIMS) throw new JwtInspectionError(`token carries more than ${JWT_MAX_CLAIMS} claims`);

  const policy: Required<JwtPolicyExpectations> = {
    requireExpiry: opts.policy?.requireExpiry ?? true,
    maxLifetimeSeconds: opts.policy?.maxLifetimeSeconds ?? 86_400,
    expectedIssuer: opts.policy?.expectedIssuer ?? "",
    expectedAudience: opts.policy?.expectedAudience ?? "",
    asymmetricExpected: opts.policy?.asymmetricExpected ?? false,
  };

  const alg = typeof header.alg === "string" ? header.alg : "";
  const claimsSummary: Record<string, unknown> = {};
  for (const key of claimKeys.sort()) claimsSummary[key] = redactClaimValue(key, payload[key]);

  const audience = typeof payload.aud === "string" ? [payload.aud] : Array.isArray(payload.aud) ? payload.aud.filter((a): a is string => typeof a === "string") : undefined;
  const expIso = isoFromEpochSeconds(payload.exp);
  const nbfIso = isoFromEpochSeconds(payload.nbf);
  const iatIso = isoFromEpochSeconds(payload.iat);
  const lifetime = typeof payload.exp === "number" && typeof payload.iat === "number" ? payload.exp - payload.iat : undefined;

  const profile: NormalizedJwtProfile = {
    fingerprint: jwtFingerprint(token),
    algorithm: alg || "UNKNOWN",
    ...(typeof header.typ === "string" ? { tokenType: header.typ } : {}),
    ...(typeof header.kid === "string" ? { keyId: header.kid.slice(0, 64) } : {}),
    ...(typeof payload.iss === "string" ? { issuer: payload.iss } : {}),
    ...(audience ? { audience } : {}),
    ...(expIso ? { expiresAt: expIso } : {}),
    ...(nbfIso ? { notBefore: nbfIso } : {}),
    ...(iatIso ? { issuedAt: iatIso } : {}),
    ...(lifetime !== undefined && lifetime > 0 ? { lifetimeSeconds: lifetime } : {}),
    claimsSummary,
    source: opts.source,
    ...(opts.host ? { host: opts.host } : {}),
    ...(opts.endpoint ? { endpoint: opts.endpoint } : {}),
  };

  const findings: JwtCheckFinding[] = [];
  const observations: string[] = [];
  const add = (vulnClass: string, severity: JwtCheckFinding["severity"], title: string, description: string, confidence = 0.9) => {
    findings.push({ vulnClass, severity, title, description, confidence, ...(owaspApiCategoryFor(vulnClass) ? { owaspCategory: owaspApiCategoryFor(vulnClass) } : {}) });
  };

  // §24: unexpected algorithm configuration.
  if (KNOWN_WEAK_ALGS.includes(alg)) {
    add("JWT_ALGORITHM_CONFIGURATION", "HIGH", "JWT Uses 'none' or Missing Algorithm", "The token's alg header is 'none' or absent. If the API accepts such tokens, signatures are not verified and any party can mint tokens. Confirm the API rejects unsigned tokens; the platform reports the configuration signal only — it does not attempt to exploit it.");
  } else if (!STRONG_ASYMMETRIC_ALGS.includes(alg) && !SYMMETRIC_ALGS.includes(alg)) {
    add("JWT_ALGORITHM_CONFIGURATION", "MEDIUM", "JWT Uses an Unexpected Algorithm", `The token uses alg '${alg}', which is outside the platform's expected algorithm set. Unexpected algorithms are a configuration risk (algorithm confusion class) and should be pinned server-side.`);
  } else if (SYMMETRIC_ALGS.includes(alg)) {
    if (policy.asymmetricExpected) {
      add("JWT_ALGORITHM_CONFIGURATION", "LOW", "JWT Uses a Symmetric Signing Algorithm", `The token uses ${alg} while policy expects asymmetric signing for this API — every verifier holds the signing secret, widening the impact of a verifier compromise.`);
    } else {
      observations.push(`Symmetric algorithm ${alg} in use — acceptable for first-party services when the secret is strongly managed; not labelled a vulnerability (§24).`);
    }
  }
  if (typeof header.kid === "string" && /(\.\.|['"\\;]|--|\/\*)/.test(header.kid)) {
    add("JWT_ALGORITHM_CONFIGURATION", "LOW", "JWT kid Header Contains Suspicious Characters", "The kid header contains characters associated with path-traversal or injection patterns. Servers must treat kid as an opaque key identifier and never as a path or query fragment.");
  }
  if (typeof header.jku === "string" || typeof header.x5u === "string") {
    observations.push("Token header references a remote key URL (jku/x5u) — the verifier must allowlist key locations; reported as an observation, not a finding.");
  }

  // §24: expiry policy.
  if (payload.exp === undefined) {
    if (policy.requireExpiry) {
      add("JWT_MISSING_EXPIRY", "MEDIUM", "JWT Has No Expiry Claim", "The token carries no 'exp' claim while platform policy expects expiry. Non-expiring bearer tokens remain valid indefinitely when leaked.");
    } else {
      observations.push("Token has no exp claim; policy does not require expiry for this profile.");
    }
  } else if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) {
    observations.push("Token is already expired (exp in the past) — recorded as metadata; an expired test token is not a vulnerability.");
  }
  if (lifetime !== undefined && lifetime > policy.maxLifetimeSeconds) {
    add("JWT_EXCESSIVE_LIFETIME", "LOW", "JWT Lifetime Exceeds Policy", `Token lifetime is ${Math.round(lifetime / 3600)}h, above the policy maximum of ${Math.round(policy.maxLifetimeSeconds / 3600)}h. Long-lived bearer tokens widen the replay window when stolen.`, 0.8);
  }

  // §24: sensitive information in readable claims.
  const sensitiveFound = claimKeys.filter((k) => SENSITIVE_CLAIM_KEYS.some((s) => k.toLowerCase().includes(s)));
  if (sensitiveFound.length > 0) {
    add("JWT_SENSITIVE_CLAIMS", "MEDIUM", "JWT Exposes Sensitive Information in Claims", `The token payload exposes sensitive claim(s): ${sensitiveFound.join(", ")}. JWT payloads are base64url-encoded, not encrypted — anyone holding the token can read them. Values are redacted in this record (§25).`);
  }

  // §24: issuer/audience consistency where configured.
  if (policy.expectedIssuer && typeof payload.iss === "string" && payload.iss !== policy.expectedIssuer) {
    add("JWT_ISSUER_AUDIENCE_MISMATCH", "MEDIUM", "JWT Issuer Does Not Match Policy", `Token issuer '${payload.iss}' differs from the configured expected issuer. Cross-issuer acceptance enables token confusion between environments.`);
  }
  if (policy.expectedAudience && audience && !audience.includes(policy.expectedAudience)) {
    add("JWT_ISSUER_AUDIENCE_MISMATCH", "MEDIUM", "JWT Audience Does Not Match Policy", `Token audience [${audience.join(", ")}] does not include the configured expected audience '${policy.expectedAudience}'.`);
  }
  if (header.typ === undefined) observations.push("Token has no typ header — common and not, by itself, a vulnerability (§24).");

  return { profile, findings, observations };
}
