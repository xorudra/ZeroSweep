/**
 * Self-hosted / enterprise product licensing (Prompt 40 §28–§37).
 *
 * Licenses are Ed25519-signed JSON documents. The application ships ONLY
 * the verification public key (§31); the private signing key lives with
 * the issuer, outside the product and outside its backups (§248).
 * Verification is fully offline (§36) — there is no phone-home (§37).
 *
 * Expiry never destroys data (§33/§35): an expired or invalid license
 * restricts paid capabilities per policy while login, data export and
 * admin recovery keep working.
 */
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";

export interface LicensePayload {
  licenseId: string;
  organization: string;
  edition: string;
  issuer: string;
  issuedAt: string; // ISO 8601
  validFrom: string; // ISO 8601
  expiresAt: string; // ISO 8601
  entitlements: Array<{ featureKey: string; enabled: boolean; limit: number | null }>;
  limits: Record<string, number | null>;
  /** Revocation list version the issuer stamped at issuance time. */
  revocationEpoch?: number;
}

export interface SignedLicense {
  payload: LicensePayload;
  /** Base64 Ed25519 signature over canonicalLicenseBytes(payload). */
  signature: string;
  algorithm: "Ed25519";
}

/** Canonical serialization: stable key order so signatures are portable. */
export function canonicalLicenseBytes(payload: LicensePayload): Buffer {
  const canonical = {
    licenseId: payload.licenseId,
    organization: payload.organization,
    edition: payload.edition,
    issuer: payload.issuer,
    issuedAt: payload.issuedAt,
    validFrom: payload.validFrom,
    expiresAt: payload.expiresAt,
    entitlements: [...payload.entitlements]
      .map((e) => ({ featureKey: e.featureKey, enabled: e.enabled, limit: e.limit }))
      .sort((a, b) => a.featureKey.localeCompare(b.featureKey)),
    limits: Object.fromEntries(Object.entries(payload.limits).sort(([a], [b]) => a.localeCompare(b))),
    revocationEpoch: payload.revocationEpoch ?? 0,
  };
  return Buffer.from(JSON.stringify(canonical), "utf8");
}

/** Issuer-side signing (used by issuer tooling and tests — never by the app at runtime). */
export function signLicense(payload: LicensePayload, privateKeyPem: string): SignedLicense {
  const key = createPrivateKey(privateKeyPem);
  const signature = edSign(null, canonicalLicenseBytes(payload), key);
  return { payload, signature: signature.toString("base64"), algorithm: "Ed25519" };
}

export type LicenseValidationStatus = "VALID" | "EXPIRING" | "EXPIRED" | "INVALID" | "REVOKED" | "NOT_YET_VALID";

export interface LicenseEvaluation {
  status: LicenseValidationStatus;
  /** True when paid capabilities may be used (VALID, EXPIRING, or inside grace). */
  capabilitiesActive: boolean;
  inGracePeriod: boolean;
  daysUntilExpiry: number | null;
  reason: string;
}

export interface LicenseEvaluationOptions {
  now: Date;
  graceDays: number;
  /** Days before expiry at which status becomes EXPIRING (§112). */
  expiringWindowDays?: number;
  /** License IDs revoked by the deployment's local revocation list. */
  revokedLicenseIds?: ReadonlySet<string>;
  /** Expected organization binding (deployment's licensed organization). */
  expectedOrganization?: string | null;
}

/**
 * Verify + evaluate a signed license (§31–§35). Any modification to the
 * payload invalidates the signature (§32/§215).
 */
export function evaluateLicense(
  license: SignedLicense,
  publicKeyPem: string,
  options: LicenseEvaluationOptions,
): LicenseEvaluation {
  const fail = (status: LicenseValidationStatus, reason: string): LicenseEvaluation => ({
    status, capabilitiesActive: false, inGracePeriod: false, daysUntilExpiry: null, reason,
  });

  if (!license || license.algorithm !== "Ed25519" || typeof license.signature !== "string" || !license.payload) {
    return fail("INVALID", "License document is malformed.");
  }
  let signatureOk = false;
  try {
    const key = createPublicKey(publicKeyPem);
    signatureOk = edVerify(null, canonicalLicenseBytes(license.payload), key, Buffer.from(license.signature, "base64"));
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) return fail("INVALID", "License signature verification failed (tampered or wrong issuer key).");

  const p = license.payload;
  if (options.revokedLicenseIds?.has(p.licenseId)) {
    return fail("REVOKED", "License has been revoked by the issuer.");
  }
  if (options.expectedOrganization && p.organization !== options.expectedOrganization) {
    return fail("INVALID", "License is issued to a different organization.");
  }

  const now = options.now.getTime();
  const validFrom = Date.parse(p.validFrom);
  const expiresAt = Date.parse(p.expiresAt);
  if (Number.isNaN(validFrom) || Number.isNaN(expiresAt)) {
    return fail("INVALID", "License validity dates are malformed.");
  }
  const daysUntilExpiry = Math.floor((expiresAt - now) / 86_400_000);
  if (now < validFrom) {
    return { status: "NOT_YET_VALID", capabilitiesActive: false, inGracePeriod: false, daysUntilExpiry, reason: "License is not yet valid." };
  }
  if (now > expiresAt) {
    const graceMs = options.graceDays * 86_400_000;
    const inGrace = options.graceDays > 0 && now <= expiresAt + graceMs;
    return {
      status: "EXPIRED",
      capabilitiesActive: inGrace,
      inGracePeriod: inGrace,
      daysUntilExpiry,
      reason: inGrace
        ? "License expired; paid capabilities remain available during the configured grace period. Customer data is preserved."
        : "License expired and the grace period has ended. Paid capabilities are restricted; customer data, login and export are preserved.",
    };
  }
  const expiringWindow = options.expiringWindowDays ?? 30;
  if (daysUntilExpiry <= expiringWindow) {
    return { status: "EXPIRING", capabilitiesActive: true, inGracePeriod: false, daysUntilExpiry, reason: "License is valid and approaching expiry." };
  }
  return { status: "VALID", capabilitiesActive: true, inGracePeriod: false, daysUntilExpiry, reason: "License is valid." };
}

/** Parse an uploaded license file's text (§111). Throws on malformed input. */
export function parseLicenseDocument(text: string): SignedLicense {
  const parsed = JSON.parse(text) as SignedLicense;
  if (!parsed || typeof parsed !== "object" || !parsed.payload || typeof parsed.signature !== "string") {
    throw new Error("Not a signed license document.");
  }
  return parsed;
}
