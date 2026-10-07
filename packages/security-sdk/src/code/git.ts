import { blockedTargetReason } from "../scope/scope.matcher";
import type { SourceScanBudget } from "./types";

/**
 * Git acquisition safety (Prompt 12 §7/§8). Clone plans are ARGUMENT
 * ARRAYS built from validated fields only — never shell strings. Hooks
 * are disabled, the credential helper is emptied, terminal prompts are
 * off, and NO credential ever appears in the URL (private access uses
 * secret references resolved by the worker's credential broker, §4).
 * Repository URLs pass the same SSRF rules as every other target
 * (Phase 3): loopback / link-local / metadata / private destinations
 * are blocked unless an approved internal engagement covers them.
 */

export interface RepositoryUrlVerdict {
  ok: boolean;
  errors: string[];
  protocol?: string;
  host?: string;
}

const ALLOWED_PROTOCOLS = ["https:", "ssh:", "git:"];

export function validateRepositoryUrl(rawUrl: string, opts: { allowInternal?: boolean } = {}): RepositoryUrlVerdict {
  const errors: string[] = [];
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, errors: ["repository URL is not a valid URL"] };
  }
  if (!ALLOWED_PROTOCOLS.includes(url.protocol)) {
    errors.push(`repository protocol ${url.protocol} is not allowed (https/ssh/git only, §8)`);
  }
  if (url.username || url.password) {
    errors.push("repository URL must not embed credentials — private access uses secret references only (§4)");
  }
  if (!url.hostname) errors.push("repository URL has no host");
  // SSH scp-style (git@host:path) is normalized by callers to ssh:// first.
  const host = url.hostname;
  if (host && !opts.allowInternal) {
    const blocked = blockedTargetReason(host);
    if (blocked) errors.push(`repository host blocked by SSRF policy: ${blocked}`);
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|fc00:|fe80:)/i.test(host) || host.endsWith(".local") || host.endsWith(".internal")) {
      errors.push("private/internal repository hosts require an approved internal engagement (§8)");
    }
  }
  if (host && opts.allowInternal) {
    const blocked = blockedTargetReason(host);
    // Even for internal engagements, cloud metadata + loopback stay blocked.
    if (blocked && /metadata|loopback/i.test(blocked)) errors.push(`repository host blocked by SSRF policy: ${blocked}`);
  }
  return { ok: errors.length === 0, errors, protocol: url.protocol, host: host || undefined };
}

export interface GitClonePlan {
  executable: "git";
  args: string[];
  /** Environment for the clone process: prompts + credential helpers off. */
  environment: Record<string, string>;
  timeoutSeconds: number;
  depth: number;
  /** Always true — credentials come from secret references, never URLs. */
  credentialHelperDisabled: true;
  hooksDisabled: true;
}

/**
 * Build the ONLY clone invocation the platform may run (§7): bounded
 * depth, single branch, no tags, no hooks, no credential helper, no
 * template hooks, terminal prompts disabled.
 */
export function buildGitClonePlan(input: {
  url: string;
  destination: string;
  branch?: string;
  budget: SourceScanBudget;
}): GitClonePlan {
  const depth = Math.max(1, input.budget.maxHistoryDepth);
  const args = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "-c", "core.fsmonitor=false",
    "clone",
    "--depth", String(depth),
    "--single-branch",
    "--no-tags",
    "--no-checkout",
    ...(input.branch ? ["--branch", input.branch] : []),
    "--",
    input.url,
    input.destination,
  ];
  return {
    executable: "git",
    args,
    environment: {
      GIT_TERMINAL_PROMPT: "0",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_ALLOW_PROTOCOL: "https,ssh,git",
    },
    timeoutSeconds: Math.min(input.budget.maxScanDurationSeconds, 900),
    depth,
    credentialHelperDisabled: true,
    hooksDisabled: true,
  };
}
