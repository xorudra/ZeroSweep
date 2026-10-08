import { describe, it, expect } from "vitest";
import { createHash, createSign, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import {
  normalizeEmail, emailDomain, generateTotpSecret, totp, verifyTotp, base32Decode,
  generateRecoveryCodes, hashRecoveryCode, verifyRecoveryCode,
  generatePkcePair, verifyPkce, validateIdToken, validateDiscovery, mapOidcClaims,
  buildSignedResponse, validateSamlResponse, mapSamlAttributes, parseXml,
  parseScimFilter, evaluateScimFilter, ScimFilterError,
  evaluatePermission, assuranceForMethods, stepUpFresh, clampSessionPolicy, sessionExpired,
  generateApiKey, verifyApiKey, validateApiScopes, scopeAllows, apiKeyUsable,
  evaluatePassword, DEFAULT_PASSWORD_POLICY, evaluateAuthRisk,
  validatePostLoginRedirect, corsOriginAllowed, encryptSecret, decryptSecret, platformKeyFromMaterial,
  cborDecode, verifyRegistration, verifyAssertion,
} from "./index";

/* ------------------------------ CBOR encoder for fixtures ------------------ */
function cborEncode(value: unknown): Buffer {
  if (typeof value === "number" && Number.isInteger(value)) {
    if (value >= 0) return encodeHead(0, value);
    return encodeHead(1, -1 - value);
  }
  if (value instanceof Buffer) return Buffer.concat([encodeHead(2, value.length), value]);
  if (typeof value === "string") { const b = Buffer.from(value, "utf8"); return Buffer.concat([encodeHead(3, b.length), b]); }
  if (Array.isArray(value)) return Buffer.concat([encodeHead(4, value.length), ...value.map(cborEncode)]);
  if (value instanceof Map) {
    const parts = [encodeHead(5, value.size)];
    for (const [k, v] of value) parts.push(cborEncode(k), cborEncode(v));
    return Buffer.concat(parts);
  }
  throw new Error("unsupported fixture value");
}
function encodeHead(major: number, arg: number): Buffer {
  if (arg < 24) return Buffer.from([(major << 5) | arg]);
  if (arg < 256) return Buffer.from([(major << 5) | 24, arg]);
  if (arg < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(arg, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(arg, 1); return b;
}

describe("email normalization (§18)", () => {
  it("trims and lowercases without provider alias rules", () => {
    expect(normalizeEmail("  Rudra.Singh@Example.COM ")).toBe("rudra.singh@example.com");
    expect(normalizeEmail("a+tag@example.com")).toBe("a+tag@example.com");
    expect(emailDomain("x@Sub.Example.com")).toBe("sub.example.com");
  });
});

describe("secret encryption (§27)", () => {
  it("AES-256-GCM round-trips and never contains the plaintext", () => {
    const key = platformKeyFromMaterial("test-platform-material");
    const ct = encryptSecret("JBSWY3DPEHPK3PXP", key);
    expect(ct).not.toContain("JBSWY3DPEHPK3PXP");
    expect(decryptSecret(ct, key)).toBe("JBSWY3DPEHPK3PXP");
    expect(() => decryptSecret(ct, platformKeyFromMaterial("other"))).toThrow();
  });
});

describe("TOTP (§26/28, §119)", () => {
  it("enrolls, verifies a correct code, rejects wrong and replayed codes", () => {
    const { secret } = generateTotpSecret();
    const now = 1_700_000_000_000;
    const { code, step } = totp(secret, now);
    const first = verifyTotp(secret, code, now, null);
    expect(first.ok).toBe(true);
    expect(first.matchedStep).toBe(step);
    const replay = verifyTotp(secret, code, now, first.matchedStep);
    expect(replay.ok).toBe(false);
    expect(replay.reason).toBe("REPLAY");
    expect(verifyTotp(secret, "000000", now, null).ok).toBe(false);
    const decoded = base32Decode("JBSWY3DPEHPK3PXP");
    expect(decoded.length).toBeGreaterThan(0);
  });
});

describe("recovery codes (§29/30, §120)", () => {
  it("hashes only, verifies once semantics via hash match", () => {
    const codes = generateRecoveryCodes(3);
    const hash = hashRecoveryCode(codes[0]);
    expect(hash).not.toContain(codes[0].replace("-", ""));
    expect(verifyRecoveryCode(codes[0], hash)).toBe(true);
    expect(verifyRecoveryCode(codes[1], hash)).toBe(false);
  });
});

describe("PKCE + OIDC (§50/51, §125/126)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" }) as never;
  const jwks = { keys: [{ ...(jwk as Record<string, unknown>), kid: "fixture-1" } as never] };
  const now = 1_700_000_000_000;
  function mintIdToken(overrides: Record<string, unknown> = {}, signKey = privateKey): string {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "fixture-1", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({
      iss: "https://idp.example.com", aud: "dsr-client", sub: "user-1", email: "rudra@example.com",
      name: "Rudra", groups: ["staff"], nonce: "nonce-1", iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 600, ...overrides,
    })).toString("base64url");
    const signer = createSign("RSA-SHA256");
    signer.update(`${header}.${payload}`);
    return `${header}.${payload}.${signer.sign(signKey, "base64url")}`;
  }
  it("PKCE S256 verifies", () => {
    const pair = generatePkcePair(Buffer.from("fixture-random-verifier-material-0123456789"));
    expect(verifyPkce(pair.verifier, pair.challenge)).toBe(true);
    expect(verifyPkce("wrong", pair.challenge)).toBe(false);
  });
  it("accepts a valid id_token and maps claims via configured names only", () => {
    const claims = validateIdToken({ idToken: mintIdToken(), jwks, expectedIssuer: "https://idp.example.com", expectedAudience: "dsr-client", expectedNonce: "nonce-1", nowMs: now });
    const mapped = mapOidcClaims(claims, { emailClaim: "email", nameClaim: "name", groupsClaim: "groups", subjectClaim: "sub" });
    expect(mapped.email).toBe("rudra@example.com");
    expect(mapped.groups).toEqual(["staff"]);
  });
  it("rejects wrong issuer, wrong audience, bad signature, expired token and nonce mismatch", () => {
    const base = { jwks, expectedIssuer: "https://idp.example.com", expectedAudience: "dsr-client", expectedNonce: "nonce-1", nowMs: now };
    expect(() => validateIdToken({ ...base, idToken: mintIdToken({ iss: "https://evil.example.com" }) })).toThrow(/issuer/);
    expect(() => validateIdToken({ ...base, idToken: mintIdToken({ aud: "other-client" }) })).toThrow(/audience/);
    const { privateKey: otherKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(() => validateIdToken({ ...base, idToken: mintIdToken({}, otherKey) })).toThrow(/signature/);
    expect(() => validateIdToken({ ...base, idToken: mintIdToken({ exp: Math.floor(now / 1000) - 3600 }) })).toThrow(/expired/);
    expect(() => validateIdToken({ ...base, idToken: mintIdToken({ nonce: "attacker" }) })).toThrow(/nonce/);
  });
  it("validates discovery documents against the configured issuer", () => {
    const doc = validateDiscovery({ issuer: "https://idp.example.com", authorization_endpoint: "https://idp.example.com/auth", token_endpoint: "https://idp.example.com/token", jwks_uri: "https://idp.example.com/jwks", response_types_supported: ["code"] }, "https://idp.example.com");
    expect(doc.tokenEndpoint).toContain("/token");
    expect(() => validateDiscovery({ issuer: "https://evil.example.com", authorization_endpoint: "https://idp.example.com/auth", token_endpoint: "https://idp.example.com/token", jwks_uri: "https://idp.example.com/jwks" }, "https://idp.example.com")).toThrow(/issuer/);
  });
});

describe("SAML (§54/55, §127/128)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const idpPublicPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const now = 1_700_000_000_000;
  const fixture = {
    idpEntityId: "https://idp.example.com/entity",
    spEntityId: "https://app.example.com/sp",
    acsUrl: "https://app.example.com/auth/saml/acs",
    nameId: "rudra@example.com",
    attributes: { email: ["rudra@example.com"], displayName: ["Rudra"], groups: ["staff"] },
    nowMs: now,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
  const validation = { idpEntityId: fixture.idpEntityId, idpCertificatePem: idpPublicPem, spEntityId: fixture.spEntityId, acsUrl: fixture.acsUrl, nowMs: now };
  it("rejects XXE outright (§128)", () => {
    expect(() => parseXml(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`)).toThrow(/DOCTYPE\/ENTITY/);
    expect(() => validateSamlResponse({ ...validation, responseXml: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` })).toThrow(/DOCTYPE\/ENTITY/);
  });
  it("accepts a properly signed assertion and maps attributes via config", () => {
    const xml = buildSignedResponse(fixture);
    const identity = validateSamlResponse({ ...validation, responseXml: xml });
    expect(identity.nameId).toBe("rudra@example.com");
    expect(identity.assertionId).toBeTruthy();
    const mapped = mapSamlAttributes(identity, { emailAttribute: "email", nameAttribute: "displayName", groupsAttribute: "groups" });
    expect(mapped).toEqual({ email: "rudra@example.com", displayName: "Rudra", groups: ["staff"] });
  });
  it("rejects unsigned assertions, tampered content and wrong-key signatures", () => {
    const signed = buildSignedResponse(fixture);
    const unsigned = signed.replace(/<ds:Signature>[\s\S]*?<\/ds:Signature>/, "");
    expect(() => validateSamlResponse({ ...validation, responseXml: unsigned })).toThrow(/not signed/);
    const tampered = signed.replace("Rudra", "Attacker");
    expect(() => validateSamlResponse({ ...validation, responseXml: tampered })).toThrow(/digest|signature/);
    const { privateKey: otherKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const wrongKey = buildSignedResponse({ ...fixture, privateKeyPem: otherKey.export({ format: "pem", type: "pkcs8" }).toString() });
    expect(() => validateSamlResponse({ ...validation, responseXml: wrongKey })).toThrow(/signature/);
  });
  it("rejects expired assertions, wrong audience and wrong recipient", () => {
    const expired = buildSignedResponse({ ...fixture, notOnOrAfterOffsetMs: -10 * 60_000, notBeforeOffsetMs: -20 * 60_000 });
    expect(() => validateSamlResponse({ ...validation, responseXml: expired })).toThrow(/expired|not yet/);
    expect(() => validateSamlResponse({ ...validation, spEntityId: "https://other.example.com/sp", responseXml: buildSignedResponse(fixture) })).toThrow(/audience/);
    expect(() => validateSamlResponse({ ...validation, acsUrl: "https://app.example.com/other", responseXml: buildSignedResponse(fixture) })).toThrow(/recipient/);
  });
});

describe("SCIM filter (§72, §132)", () => {
  it("parses and evaluates the supported subset", () => {
    const f = parseScimFilter('userName eq "rudra@example.com" and active eq "true"');
    expect(evaluateScimFilter(f, { userName: "rudra@example.com", active: true })).toBe(true);
    expect(evaluateScimFilter(f, { userName: "other@example.com", active: true })).toBe(false);
    const g = parseScimFilter('displayName co "rud" or not (active eq "true")');
    expect(evaluateScimFilter(g, { displayName: "Rudra", active: true })).toBe(true);
    expect(evaluateScimFilter(parseScimFilter("userName pr"), { userName: "x" })).toBe(true);
  });
  it("rejects injection-shaped and unsupported filters", () => {
    expect(() => parseScimFilter('userName eq "x" ; DROP TABLE users')).toThrow(ScimFilterError);
    expect(() => parseScimFilter('password eq "x"')).toThrow(ScimFilterError);
    expect(() => parseScimFilter('userName eq "x" union select')).toThrow(ScimFilterError);
    expect(() => parseScimFilter('userName xx "x"')).toThrow(ScimFilterError);
  });
});

describe("permission evaluation (§10/11)", () => {
  it("org baseline + workspace grants, explicit deny wins", () => {
    expect(evaluatePermission({ organizationRole: "MEMBER", resource: "workspace", action: "read" }).decision).toBe("ALLOW");
    expect(evaluatePermission({ organizationRole: "MEMBER", resource: "findings", action: "read" }).decision).toBe("DENY");
    expect(evaluatePermission({ organizationRole: "MEMBER", workspaceRole: "MEMBER", resource: "findings", action: "read" }).decision).toBe("ALLOW");
    expect(evaluatePermission({ organizationRole: "MEMBER", resource: "sso", action: "manage" }).decision).toBe("DENY");
    expect(evaluatePermission({ organizationRole: "VIEWER", workspaceRole: "SECURITY_ENGINEER", resource: "scans", action: "create-safe" }).decision).toBe("ALLOW");
    expect(evaluatePermission({ organizationRole: "OWNER", explicitDenies: ["org:manage"], resource: "org", action: "manage" }).decision).toBe("DENY");
  });
  it("assurance mapping and step-up freshness (§35/37)", () => {
    expect(assuranceForMethods(["PASSWORD"])).toBe("AAL1");
    expect(assuranceForMethods(["PASSWORD", "TOTP"])).toBe("AAL2");
    expect(assuranceForMethods(["PASSWORD", "PASSKEY"])).toBe("PHISHING_RESISTANT");
    expect(stepUpFresh(1000, 1000 + 5 * 60_000)).toBe(true);
    expect(stepUpFresh(1000, 1000 + 11 * 60_000)).toBe(false);
    expect(stepUpFresh(null, 5000)).toBe(false);
  });
  it("session policy clamping + expiry (§42)", () => {
    const clamped = clampSessionPolicy(1, 999999);
    expect(clamped.idleMinutes).toBe(5);
    expect(sessionExpired({ createdAtMs: 0, lastSeenAtMs: 0, idleMinutes: 30, absoluteMinutes: 720, revokedAtMs: 5 }, 100)).toBe("REVOKED");
    expect(sessionExpired({ createdAtMs: 0, lastSeenAtMs: 0, idleMinutes: 30, absoluteMinutes: 720, revokedAtMs: null }, 31 * 60_000)).toBe("IDLE_TIMEOUT");
  });
});

describe("API keys (§76–83, §133–135)", () => {
  it("plaintext shown once, hash only stored, scopes are a closed catalog", () => {
    const key = generateApiKey();
    expect(key.plaintext.startsWith("dsr_live_")).toBe(true);
    expect(key.prefix.length).toBeLessThan(key.plaintext.length);
    expect(verifyApiKey(key.plaintext, key.secretHash)).toBe(true);
    expect(verifyApiKey("dsr_live_forged", key.secretHash)).toBe(false);
    expect(validateApiScopes(["findings:read"]).ok).toBe(true);
    expect(validateApiScopes(["shell:execute"]).ok).toBe(false);
    expect(validateApiScopes(["*"]).ok).toBe(false);
    expect(scopeAllows(["findings:read"], "findings:read")).toBe(true);
    expect(scopeAllows(["findings:read"], "scans:create-safe")).toBe(false);
    expect(apiKeyUsable({ secretHash: key.secretHash, revokedAtMs: 1, expiresAtMs: null }, key.plaintext, 100)).toBe("REVOKED");
    expect(apiKeyUsable({ secretHash: key.secretHash, revokedAtMs: null, expiresAtMs: 50 }, key.plaintext, 100)).toBe("EXPIRED");
    expect(apiKeyUsable({ secretHash: key.secretHash, revokedAtMs: null, expiresAtMs: null }, key.plaintext, 100)).toBeNull();
  });
});

describe("password policy + risk + redirect (§21/46/108)", () => {
  it("length-based policy", () => {
    expect(evaluatePassword("short", DEFAULT_PASSWORD_POLICY).ok).toBe(false);
    expect(evaluatePassword("a-very-long-enough-password", DEFAULT_PASSWORD_POLICY).ok).toBe(true);
  });
  it("risk responses are policy-shaped, never geo-only blocks", () => {
    const base = { newDevice: false, excessiveFailures: false, impossibleSessionState: false, suspiciousSessionReuse: false, authenticationDowngrade: false, failureCountLastHour: 0 };
    expect(evaluateAuthRisk(base).response).toBe("ALLOW");
    expect(evaluateAuthRisk({ ...base, newDevice: true }).response).toBe("REQUIRE_MFA");
    expect(evaluateAuthRisk({ ...base, suspiciousSessionReuse: true }).response).toBe("BLOCK");
  });
  it("open redirects are sanitized to local paths", () => {
    expect(validatePostLoginRedirect("https://attacker.example/phish")).toBe("/");
    expect(validatePostLoginRedirect("//attacker.example")).toBe("/");
    expect(validatePostLoginRedirect("/dashboard?tab=1")).toBe("/dashboard?tab=1");
  });
  it("CORS never allows wildcard with credentials", () => {
    expect(corsOriginAllowed("https://app.example.com", ["https://app.example.com"])).toBe("https://app.example.com");
    expect(corsOriginAllowed("https://evil.example", ["https://app.example.com"])).toBeNull();
    expect(corsOriginAllowed("https://app.example.com", ["*"])).toBeNull();
  });
});

describe("WebAuthn (§33/34, §121)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const coseKey = cborEncode(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
  const rpId = "app.example.com";
  const origin = "https://app.example.com";
  const credentialId = Buffer.from("fixture-credential-id-1");
  function authData(flags: number, counter: number, withAttested: boolean): Buffer {
    const rpHash = createHash("sha256").update(rpId).digest();
    const counterBuf = Buffer.alloc(4); counterBuf.writeUInt32BE(counter);
    if (!withAttested) return Buffer.concat([rpHash, Buffer.from([flags]), counterBuf]);
    const credLen = Buffer.alloc(2); credLen.writeUInt16BE(credentialId.length);
    return Buffer.concat([rpHash, Buffer.from([flags]), counterBuf, Buffer.alloc(16), credLen, credentialId, coseKey]);
  }
  it("cbor round-trips", () => {
    const { value } = cborDecode(cborEncode(new Map<unknown, unknown>([[1, "a"], [-2, Buffer.from("xy")]])));
    expect(value).toBeInstanceOf(Map);
  });
  it("registration verifies and assertion verifies with counter progression; replay/wrong-origin/wrong-challenge fail", () => {
    // Registration (attestation none)
    const regChallenge = Buffer.from("reg-challenge-0123456789abcdef").toString("base64url");
    const regClient = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: regChallenge, origin, crossOrigin: false }));
    const attObj = cborEncode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData(0x05 | 0x40, 0, true)]]));
    const reg = verifyRegistration({ attestationObject: attObj, clientDataJSON: regClient, check: { expectedType: "webauthn.create", expectedChallenge: regChallenge, expectedOrigin: origin }, rpId, requireUserVerification: true });
    expect(reg.credentialId).toBe(credentialId.toString("base64url"));
    // Assertion
    const authChallenge = Buffer.from("auth-challenge-0123456789abcde").toString("base64url");
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: authChallenge, origin, crossOrigin: false }));
    const ad = authData(0x05, 7, false);
    const signed = Buffer.concat([ad, createHash("sha256").update(clientData).digest()]);
    const signature = cryptoSign("sha256", signed, { key: privateKey, dsaEncoding: "der" });
    const result = verifyAssertion({ authenticatorData: ad, clientDataJSON: clientData, signature, publicKeyCoseBase64url: reg.publicKeyCoseBase64url, check: { expectedType: "webauthn.get", expectedChallenge: authChallenge, expectedOrigin: origin }, rpId, requireUserVerification: true, storedSignCount: reg.signCount });
    expect(result.signCount).toBe(7);
    // Replay: same counter as stored
    expect(() => verifyAssertion({ authenticatorData: ad, clientDataJSON: clientData, signature, publicKeyCoseBase64url: reg.publicKeyCoseBase64url, check: { expectedType: "webauthn.get", expectedChallenge: authChallenge, expectedOrigin: origin }, rpId, requireUserVerification: true, storedSignCount: 7 })).toThrow(/counter/);
    // Wrong origin
    const badOriginClient = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: authChallenge, origin: "https://evil.example", crossOrigin: false }));
    expect(() => verifyAssertion({ authenticatorData: ad, clientDataJSON: badOriginClient, signature, publicKeyCoseBase64url: reg.publicKeyCoseBase64url, check: { expectedType: "webauthn.get", expectedChallenge: authChallenge, expectedOrigin: origin }, rpId, requireUserVerification: true, storedSignCount: 0 })).toThrow(/origin/);
    // Wrong RP id
    expect(() => verifyAssertion({ authenticatorData: ad, clientDataJSON: clientData, signature, publicKeyCoseBase64url: reg.publicKeyCoseBase64url, check: { expectedType: "webauthn.get", expectedChallenge: authChallenge, expectedOrigin: origin }, rpId: "other.example.com", requireUserVerification: true, storedSignCount: 0 })).toThrow(/RP ID/);
  });
});
