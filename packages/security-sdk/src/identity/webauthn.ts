import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { sha256Hex } from "./crypto";

/** WebAuthn / passkey verification (§31–34) implemented on node:crypto:
 *  challenge, origin, RP ID hash, user-verification flag, ES256 signature
 *  over authenticatorData ‖ SHA-256(clientDataJSON), and signature-counter
 *  replay checks. Authenticator PRIVATE keys never exist server-side (§33);
 *  only the COSE public key is stored. Attestation format "none" is
 *  accepted for registration (self-attestation); the credential's trust
 *  comes from the authenticated enrollment session + step-up. */

/* ---------------- minimal CBOR decoder (maps/arrays/bytes/text/int) -------- */
export function cborDecode(input: Buffer, offset = 0): { value: unknown; next: number } {
  const first = input[offset];
  const major = first >> 5;
  let arg = first & 0x1f;
  let pos = offset + 1;
  if (arg >= 24 && arg <= 27) {
    const sizes = [1, 2, 4, 8];
    const size = sizes[arg - 24];
    let v = 0n;
    for (let i = 0; i < size; i++) v = (v << 8n) | BigInt(input[pos + i]);
    arg = Number(v);
    pos += size;
  } else if (arg >= 28) throw new Error("Unsupported CBOR additional info");
  switch (major) {
    case 0: return { value: arg, next: pos };
    case 1: return { value: -1 - arg, next: pos };
    case 2: return { value: input.subarray(pos, pos + arg), next: pos + arg };
    case 3: return { value: input.subarray(pos, pos + arg).toString("utf8"), next: pos + arg };
    case 4: {
      const arr: unknown[] = [];
      let p = pos;
      for (let i = 0; i < arg; i++) { const r = cborDecode(input, p); arr.push(r.value); p = r.next; }
      return { value: arr, next: p };
    }
    case 5: {
      const map = new Map<unknown, unknown>();
      let p = pos;
      for (let i = 0; i < arg; i++) {
        const k = cborDecode(input, p); const v = cborDecode(input, k.next);
        map.set(k.value, v.value); p = v.next;
      }
      return { value: map, next: p };
    }
    case 7: return { value: arg === 20 ? false : arg === 21 ? true : null, next: pos };
    default: throw new Error(`Unsupported CBOR major type ${major}`);
  }
}

/* ----------------------------- data structures ---------------------------- */
export interface AuthenticatorData {
  rpIdHash: Buffer;
  userPresent: boolean;
  userVerified: boolean;
  hasAttestedCredentialData: boolean;
  signCount: number;
  credentialId?: Buffer;
  credentialPublicKeyCose?: Buffer;
}

export function parseAuthenticatorData(data: Buffer): AuthenticatorData {
  if (data.length < 37) throw new Error("Authenticator data too short");
  const flags = data[32];
  const result: AuthenticatorData = {
    rpIdHash: data.subarray(0, 32),
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    hasAttestedCredentialData: (flags & 0x40) !== 0,
    signCount: data.readUInt32BE(33),
  };
  if (result.hasAttestedCredentialData) {
    const credIdLen = data.readUInt16BE(53);
    result.credentialId = data.subarray(55, 55 + credIdLen);
    result.credentialPublicKeyCose = data.subarray(55 + credIdLen);
  }
  return result;
}

/** Convert a COSE EC2/ES256 public key to a Node KeyObject. */
export function cosePublicKeyToKeyObject(cose: Buffer) {
  const { value } = cborDecode(cose);
  if (!(value instanceof Map)) throw new Error("COSE key is not a map");
  const kty = value.get(1);
  const alg = value.get(3);
  const x = value.get(-2) as Buffer | undefined;
  const y = value.get(-3) as Buffer | undefined;
  if (kty !== 2 || alg !== -7 || !x || !y) throw new Error("Only EC2/ES256 COSE keys are supported");
  return createPublicKey({
    format: "jwk",
    key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") },
  });
}

export interface ClientDataCheck {
  expectedType: "webauthn.create" | "webauthn.get";
  expectedChallenge: string; // base64url
  expectedOrigin: string;
}

export function parseAndCheckClientData(clientDataJSON: Buffer, check: ClientDataCheck): void {
  const parsed = JSON.parse(clientDataJSON.toString("utf8")) as { type?: string; challenge?: string; origin?: string };
  if (parsed.type !== check.expectedType) throw new Error(`Unexpected clientData type ${parsed.type}`);
  if (parsed.challenge !== check.expectedChallenge) throw new Error("WebAuthn challenge mismatch");
  if (parsed.origin !== check.expectedOrigin) throw new Error("WebAuthn origin mismatch");
}

function rpIdHashMatches(authData: AuthenticatorData, rpId: string): boolean {
  const expected = createHash("sha256").update(rpId, "utf8").digest();
  return expected.equals(authData.rpIdHash);
}

export interface RegistrationResult {
  credentialId: string; // base64url
  publicKeyCoseBase64url: string;
  signCount: number;
}

/** Verify a registration response (attestation format "none"). */
export function verifyRegistration(input: {
  attestationObject: Buffer;
  clientDataJSON: Buffer;
  check: ClientDataCheck;
  rpId: string;
  requireUserVerification: boolean;
}): RegistrationResult {
  parseAndCheckClientData(input.clientDataJSON, input.check);
  const { value } = cborDecode(input.attestationObject);
  if (!(value instanceof Map)) throw new Error("Attestation object is not a map");
  const fmt = value.get("fmt");
  if (fmt !== "none") throw new Error(`Unsupported attestation format ${String(fmt)}`);
  const authDataRaw = value.get("authData") as Buffer;
  const authData = parseAuthenticatorData(authDataRaw);
  if (!rpIdHashMatches(authData, input.rpId)) throw new Error("RP ID hash mismatch");
  if (!authData.userPresent) throw new Error("User presence flag missing");
  if (input.requireUserVerification && !authData.userVerified) throw new Error("User verification required");
  if (!authData.credentialId || !authData.credentialPublicKeyCose) throw new Error("Missing attested credential data");
  // Validate the COSE key parses as EC2/ES256 now so bad keys never persist.
  cosePublicKeyToKeyObject(authData.credentialPublicKeyCose);
  return {
    credentialId: authData.credentialId.toString("base64url"),
    publicKeyCoseBase64url: authData.credentialPublicKeyCose.toString("base64url"),
    signCount: authData.signCount,
  };
}

export interface AssertionResult { signCount: number; userVerified: boolean }

/** Verify an authentication assertion against the stored COSE public key. */
export function verifyAssertion(input: {
  authenticatorData: Buffer;
  clientDataJSON: Buffer;
  signature: Buffer; // ASN.1 DER ECDSA signature (WebAuthn standard)
  publicKeyCoseBase64url: string;
  check: ClientDataCheck;
  rpId: string;
  requireUserVerification: boolean;
  storedSignCount: number;
}): AssertionResult {
  parseAndCheckClientData(input.clientDataJSON, input.check);
  const authData = parseAuthenticatorData(input.authenticatorData);
  if (!rpIdHashMatches(authData, input.rpId)) throw new Error("RP ID hash mismatch");
  if (!authData.userPresent) throw new Error("User presence flag missing");
  if (input.requireUserVerification && !authData.userVerified) throw new Error("User verification required");
  const clientHash = createHash("sha256").update(input.clientDataJSON).digest();
  const signed = Buffer.concat([input.authenticatorData, clientHash]);
  const key = cosePublicKeyToKeyObject(Buffer.from(input.publicKeyCoseBase64url, "base64url"));
  const ok = cryptoVerify("sha256", signed, key, input.signature);
  if (!ok) throw new Error("WebAuthn signature verification failed");
  // Counter replay/clone detection (§34): counters must strictly increase
  // when the authenticator supports them.
  if (input.storedSignCount > 0 || authData.signCount > 0) {
    if (authData.signCount <= input.storedSignCount) throw new Error("WebAuthn signature counter did not increase");
  }
  return { signCount: authData.signCount, userVerified: authData.userVerified };
}

export function challengeHash(challenge: string): string {
  return sha256Hex(challenge);
}
