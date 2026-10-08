import type { EasmCertificateState } from "./types";

/**
 * Certificate intelligence (Prompt 29 §35–§39). Certificates are
 * tracked by fingerprint; SAN entries create ownership CANDIDATES
 * (§37) — a SAN mention is weak evidence and never an authorization.
 */

export interface CertificateThresholds {
  /** Days remaining at/below which a cert is EXPIRING. */
  expiringDays: number;
  /** Days remaining at/below which a cert is URGENT. */
  urgentDays: number;
}

export const DEFAULT_CERTIFICATE_THRESHOLDS: CertificateThresholds = { expiringDays: 30, urgentDays: 7 };

export function certificateState(notAfter: Date, now: Date, thresholds: CertificateThresholds = DEFAULT_CERTIFICATE_THRESHOLDS): EasmCertificateState {
  const msLeft = notAfter.getTime() - now.getTime();
  if (msLeft <= 0) return "EXPIRED";
  const daysLeft = msLeft / 86_400_000;
  if (daysLeft <= thresholds.urgentDays) return "URGENT";
  if (daysLeft <= thresholds.expiringDays) return "EXPIRING";
  return "HEALTHY";
}

export type CertificateChangeKind = "CERTIFICATE_ADDED" | "CERTIFICATE_REPLACED" | "CERTIFICATE_EXPIRED" | "CERTIFICATE_EXPIRING";

export interface CertificateChangeEvent {
  kind: CertificateChangeKind;
  host: string;
  beforeFingerprint: string | null;
  afterFingerprint: string | null;
  detail: string;
}

/**
 * §39: compare the certificate currently observed for a host against
 * the previously recorded one. ADDED = first observation; REPLACED =
 * fingerprint changed; EXPIRED/EXPIRING = health-state transitions
 * into those states (emitted once, on transition).
 */
export function diffCertificate(input: {
  host: string;
  before: { fingerprint: string; state: EasmCertificateState } | null;
  after: { fingerprint: string; state: EasmCertificateState } | null;
}): CertificateChangeEvent[] {
  const events: CertificateChangeEvent[] = [];
  const { host, before, after } = input;
  if (!before && after) {
    events.push({ kind: "CERTIFICATE_ADDED", host, beforeFingerprint: null, afterFingerprint: after.fingerprint, detail: "first certificate observed for host" });
  } else if (before && after && before.fingerprint !== after.fingerprint) {
    events.push({ kind: "CERTIFICATE_REPLACED", host, beforeFingerprint: before.fingerprint, afterFingerprint: after.fingerprint, detail: "certificate fingerprint changed" });
  }
  if (after && after.state === "EXPIRED" && before?.state !== "EXPIRED") {
    events.push({ kind: "CERTIFICATE_EXPIRED", host, beforeFingerprint: before?.fingerprint ?? null, afterFingerprint: after.fingerprint, detail: "certificate has expired" });
  } else if (after && (after.state === "EXPIRING" || after.state === "URGENT") && before && before.state === "HEALTHY") {
    events.push({ kind: "CERTIFICATE_EXPIRING", host, beforeFingerprint: before.fingerprint, afterFingerprint: after.fingerprint, detail: `certificate entered ${after.state} state` });
  }
  return events;
}
