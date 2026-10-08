/**
 * Prompt 34 — CloudResourceSnapshot (§17) and configuration drift
 * (§18).
 *
 * A snapshot is the immutable, bounded, SANITIZED security
 * configuration of one cloud resource. Sanitization is structural:
 * secret-shaped keys are dropped and secret-shaped values are
 * redacted before hashing or storage, so a synthetic secret planted
 * in provider output can never reach storage, reports or AI context
 * (§147). Drift compares two snapshots of the same resource and
 * classifies the change; a change is an observation with a risk
 * signal — never an automatic malicious verdict.
 */
import { createHash } from "node:crypto";
import { looksLikeSecretValue, redactSecretShapes } from "../cloudsec/guards";
import type { NormalizedCloudResource } from "../findings/finding.types";

const SECRET_KEY_RE = /(secret|password|passwd|token|private[_-]?key|access[_-]?key|credential|api[_-]?key)/i;
const MAX_SNAPSHOT_KEYS = 64;
const MAX_SNAPSHOT_DEPTH = 4;

function sanitizeValue(value: unknown, depth: number): unknown {
  if (depth > MAX_SNAPSHOT_DEPTH) return "[TRUNCATED]";
  if (typeof value === "string") {
    if (looksLikeSecretValue(value)) return "[REDACTED]";
    return redactSecretShapes(value).slice(0, 512);
  }
  if (Array.isArray(value)) return value.slice(0, 32).map((v) => sanitizeValue(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, MAX_SNAPSHOT_KEYS)) {
      if (SECRET_KEY_RE.test(k)) continue; // secret-bearing keys are dropped, never stored (§17/§147)
      out[k] = sanitizeValue(v, depth + 1);
    }
    return out;
  }
  return value;
}

/** Canonical (key-sorted) JSON so hashes are stable across runs. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export interface CloudResourceSnapshotData {
  configuration: Record<string, unknown>;
  configurationHash: string;
  exposure: string;
}

/** Build the storable snapshot payload for one resource (§17). */
export function buildResourceSnapshot(resource: NormalizedCloudResource): CloudResourceSnapshotData {
  const configuration = sanitizeValue(resource.configuration ?? {}, 0) as Record<string, unknown>;
  return {
    configuration,
    configurationHash: createHash("sha256").update(canonical(configuration)).digest("hex"),
    exposure: resource.exposure,
  };
}

export type CloudV2DriftKind =
  | "PUBLIC_EXPOSURE" | "SECURITY_GROUP_CHANGE" | "IAM_CHANGE"
  | "ENCRYPTION_CHANGE" | "LOGGING_DISABLED" | "LOGGING_CHANGE"
  | "RESOURCE_ADDED" | "RESOURCE_REMOVED" | "CONFIGURATION_CHANGE";

export interface CloudV2DriftEvent {
  kind: CloudV2DriftKind;
  resourceRef: string;
  detail: string;
  riskSignal: "ELEVATED" | "STANDARD";
}

function changedKeys(a: Record<string, unknown>, b: Record<string, unknown>): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((k) => canonical(a[k]) !== canonical(b[k]));
}

const KEY_KIND: Array<{ re: RegExp; kind: CloudV2DriftKind }> = [
  { re: /(securitygroup|security_group|firewall|ingress|egress|networkacl)/i, kind: "SECURITY_GROUP_CHANGE" },
  { re: /(iam|policy|role|trust|principal|permission)/i, kind: "IAM_CHANGE" },
  { re: /(encrypt|kms|sse|tls|ssl)/i, kind: "ENCRYPTION_CHANGE" },
];

/**
 * Compare two snapshots of the SAME resource (§18). Exposure moving
 * toward PUBLIC is the headline drift and is ELEVATED; logging being
 * disabled is classified distinctly from a generic logging change.
 */
export function diffResourceSnapshots(
  resourceRef: string,
  previous: CloudResourceSnapshotData,
  next: CloudResourceSnapshotData,
): CloudV2DriftEvent[] {
  const events: CloudV2DriftEvent[] = [];
  if (previous.configurationHash === next.configurationHash && previous.exposure === next.exposure) return events;

  if (previous.exposure !== next.exposure) {
    const toPublic = next.exposure === "PUBLIC";
    events.push({
      kind: "PUBLIC_EXPOSURE",
      resourceRef,
      detail: `Exposure changed ${previous.exposure} → ${next.exposure}${toPublic ? " — resource became publicly exposed" : ""}.`,
      riskSignal: toPublic ? "ELEVATED" : "STANDARD",
    });
  }
  const keys = changedKeys(previous.configuration, next.configuration);
  const loggingKeys = keys.filter((k) => /log/i.test(k));
  for (const k of loggingKeys) {
    const before = previous.configuration[k];
    const after = next.configuration[k];
    const disabled = (before === true || before === "ENABLED") && (after === false || after === "DISABLED" || after === undefined);
    events.push({
      kind: disabled ? "LOGGING_DISABLED" : "LOGGING_CHANGE",
      resourceRef,
      detail: `Logging configuration key "${k}" changed${disabled ? " — logging was disabled" : ""}.`,
      riskSignal: disabled ? "ELEVATED" : "STANDARD",
    });
  }
  const classified = new Set<CloudV2DriftKind>();
  for (const k of keys) {
    if (loggingKeys.includes(k)) continue;
    const match = KEY_KIND.find(({ re }) => re.test(k));
    if (match && !classified.has(match.kind)) {
      classified.add(match.kind);
      events.push({
        kind: match.kind,
        resourceRef,
        detail: `Configuration key "${k}" changed (${match.kind}).`,
        riskSignal: match.kind === "IAM_CHANGE" ? "ELEVATED" : "STANDARD",
      });
    }
  }
  if (events.length === 0 && keys.length > 0) {
    events.push({
      kind: "CONFIGURATION_CHANGE",
      resourceRef,
      detail: `Configuration changed (keys: ${keys.slice(0, 8).join(", ")}).`,
      riskSignal: "STANDARD",
    });
  }
  return events;
}

/** Set-level drift (§18): resources appearing or disappearing between
 *  two inventories of the same account. */
export function diffResourceSets(
  previousRefs: string[],
  nextRefs: string[],
): CloudV2DriftEvent[] {
  const prev = new Set(previousRefs);
  const next = new Set(nextRefs);
  const events: CloudV2DriftEvent[] = [];
  for (const ref of nextRefs) {
    if (!prev.has(ref)) events.push({ kind: "RESOURCE_ADDED", resourceRef: ref, detail: "New resource observed in inventory.", riskSignal: "STANDARD" });
  }
  for (const ref of previousRefs) {
    if (!next.has(ref)) events.push({ kind: "RESOURCE_REMOVED", resourceRef: ref, detail: "Resource no longer observed in inventory (record retained, never hard-deleted).", riskSignal: "STANDARD" });
  }
  return events;
}
