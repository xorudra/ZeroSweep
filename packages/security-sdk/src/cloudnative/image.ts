/**
 * Prompt 13 — container image identity & registry policy (§5–§8, §78,
 * §107).
 *
 * Digest is the strongest identity: tags are mutable lookup keys. A
 * scan records the digest it analyzed; when the same tag later resolves
 * to a new digest that is DRIFT — a new snapshot, never an overwrite.
 * Registry URLs pass the platform network/SSRF policy (private,
 * loopback, link-local and metadata destinations are denied unless the
 * registry is an explicitly approved internal one), and credentials are
 * secret references only — URLs embedding credentials are rejected.
 */
import { createHash } from "node:crypto";
import { blockedTargetReason } from "../scope/scope.matcher";
import type { ImageReference } from "./types";

const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const REPO_SEGMENT_RE = /^[a-z0-9]+(?:(?:[._]|_|[-]+)[a-z0-9]+)*$/;

export function isValidImageDigest(digest: string): boolean {
  return DIGEST_RE.test(digest);
}

/** Parse `[registry/]repository[:tag][@digest]`. Docker Hub shorthand
 *  (`nginx`, `library/nginx`) resolves to docker.io. Malformed input
 *  throws — image identity is never guessed. */
export function parseImageReference(raw: string): ImageReference {
  const input = raw.trim();
  if (!input || input.length > 1024 || /\s/.test(input)) throw new Error("invalid image reference");
  let rest = input;
  let digest: string | undefined;
  const at = rest.indexOf("@");
  if (at >= 0) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
    if (!isValidImageDigest(digest)) throw new Error("invalid image digest (expected sha256:<64 hex>)");
  }
  let tag: string | undefined;
  const lastSlash = rest.lastIndexOf("/");
  const colon = rest.lastIndexOf(":");
  if (colon > lastSlash) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
    if (!TAG_RE.test(tag)) throw new Error("invalid image tag");
  }
  const parts = rest.split("/").filter(Boolean);
  if (parts.length === 0) throw new Error("invalid image reference: empty repository");
  let registry = "docker.io";
  let repoParts = parts;
  const first = parts[0]!;
  if (parts.length > 1 && (first.includes(".") || first.includes(":") || first === "localhost")) {
    registry = first.toLowerCase();
    repoParts = parts.slice(1);
  }
  if (registry === "docker.io" && repoParts.length === 1) repoParts = ["library", repoParts[0]!];
  for (const seg of repoParts) {
    if (!REPO_SEGMENT_RE.test(seg)) throw new Error(`invalid repository segment: ${seg}`);
  }
  const repository = repoParts.join("/");
  const reference = `${registry}/${repository}${tag ? `:${tag}` : ""}${digest ? `@${digest}` : ""}`;
  return { registry, repository, ...(tag ? { tag } : {}), ...(digest ? { digest } : {}), reference };
}

/** Stable identity key for correlation/storage: digest wins (§5). */
export function imageIdentityKey(ref: Pick<ImageReference, "registry" | "repository" | "tag" | "digest">): string {
  return ref.digest
    ? `${ref.registry}/${ref.repository}@${ref.digest}`
    : `${ref.registry}/${ref.repository}:${ref.tag ?? "latest"}`;
}

/** Drift detection (§78): same tag, different digest = drift. */
export function detectImageDrift(previousDigest: string | undefined, currentDigest: string | undefined): boolean {
  return !!previousDigest && !!currentDigest && previousDigest !== currentDigest;
}

export interface RegistryUrlVerdict { allowed: boolean; reason?: string }

/**
 * Registry URL policy (§7/§107). https only; credentials embedded in
 * the URL are refused (they would leak into logs/artifacts); private /
 * loopback / link-local / metadata hosts are denied unless the caller
 * passes `approvedInternal` for an explicitly approved internal
 * registry (§107's exception is an approval, not a default).
 */
export function validateRegistryUrl(rawUrl: string, opts: { approvedInternal?: boolean } = {}): RegistryUrlVerdict {
  let url: URL;
  try { url = new URL(rawUrl); } catch { return { allowed: false, reason: "REGISTRY_URL_INVALID" }; }
  if (url.protocol !== "https:") return { allowed: false, reason: "REGISTRY_URL_NOT_HTTPS" };
  if (url.username || url.password) return { allowed: false, reason: "REGISTRY_URL_EMBEDDED_CREDENTIALS" };
  const host = url.hostname.toLowerCase();
  const blocked = blockedTargetReason(host);
  if (blocked && !opts.approvedInternal) return { allowed: false, reason: `REGISTRY_URL_BLOCKED:${blocked}` };
  return { allowed: true };
}

/** Content checksum for image config/manifest artifacts (§5/§48). */
export function cloudArtifactChecksum(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

/** Normalized base-image identity (§23): reported ONLY when a tool or
 *  the image config states it reliably — never inferred from a name
 *  that merely looks like a base image. */
export function normalizeBaseImage(raw: unknown): { registry: string; repository: string; digest?: string } | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Record<string, unknown>;
  const name = typeof r.name === "string" ? r.name : typeof r.reference === "string" ? r.reference : undefined;
  if (!name) return undefined;
  try {
    const ref = parseImageReference(name);
    return { registry: ref.registry, repository: ref.repository, ...(ref.digest ? { digest: ref.digest } : {}) };
  } catch {
    return undefined;
  }
}
