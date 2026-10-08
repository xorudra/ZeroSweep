import { blockedTargetReason } from "../scope/scope.matcher";

/**
 * Repository ingestion safety (Prompt 24 §85–§89, §117, §118).
 * Cloning/fetching is performed only by isolated workers under
 * restricted credentials; THESE pure policy functions are the
 * decision layer every ingestion path must pass first:
 *
 * - §86: provider host validation + repository allowlist (enforced
 *   again at the API service against RepositoryIntegrationLink rows);
 * - §86: submodule URLs are validated against the same policy — an
 *   arbitrary submodule URL is never followed (§117);
 * - §87/§88: size, depth and generated-file budgets + archive-bomb
 *   heuristics;
 * - §89: symlinks must never escape the checkout directory (§118).
 */

export const CLONE_POLICY = {
  maxRepoSizeBytes: 2 * 1024 * 1024 * 1024,
  maxCloneDepth: 50,
  maxFileCount: 200_000,
  maxSingleFileBytes: 100 * 1024 * 1024,
  /** §88: decompressed/compressed ratio above this is a bomb signal. */
  maxExpansionRatio: 100,
} as const;

export function validateSubmoduleUrl(
  rawUrl: string,
  policy: { allowedHosts: string[] },
): { ok: boolean; reason?: string } {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "submodule URL is not a valid URL (§117)" };
  }
  if (url.username || url.password) return { ok: false, reason: "submodule URL must not embed credentials" };
  if (url.protocol !== "https:") return { ok: false, reason: `submodule URL scheme ${url.protocol} is not allowed — https only` };
  const host = url.hostname.toLowerCase();
  const blocked = blockedTargetReason(host);
  if (blocked) return { ok: false, reason: `submodule host blocked: ${blocked} (§117)` };
  if (policy.allowedHosts.length > 0 && !policy.allowedHosts.some((h) => host === h.toLowerCase() || host.endsWith(`.${h.toLowerCase()}`))) {
    return { ok: false, reason: `submodule host ${host} is not in the ingestion allowlist (§86)` };
  }
  return { ok: true };
}

function normalizePosix(path: string): string {
  const parts: string[] = [];
  for (const seg of path.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return "/" + parts.join("/");
}

/** §89: every symlink target, resolved against its own directory,
 *  must stay inside the checkout root. Absolute targets are escapes
 *  by definition. */
export function checkSymlinkEscape(
  entries: Array<{ path: string; linkTarget?: string }>,
  checkoutRoot = "/checkout",
): { ok: boolean; violations: Array<{ path: string; linkTarget: string; resolved: string }> } {
  const root = normalizePosix(checkoutRoot);
  const violations: Array<{ path: string; linkTarget: string; resolved: string }> = [];
  for (const entry of entries) {
    if (!entry.linkTarget) continue;
    const dir = entry.path.includes("/") ? entry.path.slice(0, entry.path.lastIndexOf("/")) : "";
    const resolved = entry.linkTarget.startsWith("/")
      ? normalizePosix(entry.linkTarget)
      : normalizePosix(`${root}/${dir}/${entry.linkTarget}`);
    if (resolved !== root && !resolved.startsWith(root + "/")) {
      violations.push({ path: entry.path, linkTarget: entry.linkTarget, resolved });
    }
  }
  return { ok: violations.length === 0, violations };
}

/** §85/§87/§88: clone + archive budget checks. */
export function checkClonePolicy(input: {
  sizeBytes?: number;
  depth?: number;
  fileCount?: number;
  largestFileBytes?: number;
  compressedBytes?: number;
  decompressedBytes?: number;
}): { ok: boolean; violations: string[] } {
  const violations: string[] = [];
  if (input.sizeBytes != null && input.sizeBytes > CLONE_POLICY.maxRepoSizeBytes) {
    violations.push(`repository size ${input.sizeBytes} exceeds budget ${CLONE_POLICY.maxRepoSizeBytes} (§87)`);
  }
  if (input.depth != null && input.depth > CLONE_POLICY.maxCloneDepth) {
    violations.push(`clone depth ${input.depth} exceeds budget ${CLONE_POLICY.maxCloneDepth} (§85)`);
  }
  if (input.fileCount != null && input.fileCount > CLONE_POLICY.maxFileCount) {
    violations.push(`file count ${input.fileCount} exceeds budget ${CLONE_POLICY.maxFileCount} (§88)`);
  }
  if (input.largestFileBytes != null && input.largestFileBytes > CLONE_POLICY.maxSingleFileBytes) {
    violations.push(`largest file ${input.largestFileBytes} exceeds budget ${CLONE_POLICY.maxSingleFileBytes} (§88)`);
  }
  if (input.compressedBytes != null && input.decompressedBytes != null && input.compressedBytes > 0) {
    const ratio = input.decompressedBytes / input.compressedBytes;
    if (ratio > CLONE_POLICY.maxExpansionRatio) {
      violations.push(`expansion ratio ${ratio.toFixed(1)}x exceeds bomb threshold ${CLONE_POLICY.maxExpansionRatio}x (§88)`);
    }
  }
  return { ok: violations.length === 0, violations };
}
