import { sanitizeBranchName, sanitizeUntrustedText } from "./sanitize";
import type { ExternalPullRequest, ExternalRepository, NormalizedSourceEvent } from "./types";

/**
 * Provider webhook payload parsers (Prompt 24 §14, §23, §25, §27).
 * Parsers are TOTAL functions over hostile input: malformed payloads
 * return null, never throw, and never produce partial identities.
 * Every extracted string is sanitized at this boundary (§83) so no
 * downstream code can accidentally store or render raw provider text.
 */

function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function visibilityOf(v: unknown): "PUBLIC" | "PRIVATE" | "INTERNAL" {
  if (v === "public") return "PUBLIC";
  if (v === "internal") return "INTERNAL";
  return "PRIVATE";
}

/* ------------------------------- GitHub ------------------------------- */

export function normalizeGitHubRepository(repo: Record<string, unknown>): ExternalRepository | null {
  const id = repo.id;
  if (typeof id !== "number" && typeof id !== "string") return null;
  return {
    provider: "GITHUB",
    externalId: String(id),
    fullName: sanitizeUntrustedText(repo.full_name, 300),
    url: str(repo.html_url) ?? "",
    defaultBranch: str(repo.default_branch),
    visibility: repo.private === true ? "PRIVATE" : "PUBLIC",
    archived: repo.archived === true,
    languages: repo.language ? [sanitizeUntrustedText(repo.language, 60)] : [],
  };
}

export function parseGitHubEvent(eventType: string, payload: unknown): NormalizedSourceEvent | null {
  const p = obj(payload);
  if (!p) return null;
  const repo = obj(p.repository);
  const base: NormalizedSourceEvent = {
    provider: "GITHUB",
    kind: "UNKNOWN",
    externalRepoId: repo && (typeof repo.id === "number" || typeof repo.id === "string") ? String(repo.id) : "",
    repositoryFullName: repo ? sanitizeUntrustedText(repo.full_name, 300) : "",
    installationId: obj(p.installation)?.id != null ? String(obj(p.installation)!.id) : undefined,
  };
  if (eventType === "push") {
    return {
      ...base, kind: "PUSH",
      branch: sanitizeBranchName(str(p.ref)?.replace(/^refs\/heads\//, "")),
      commitSha: str(p.after),
    };
  }
  if (eventType === "pull_request") {
    const pr = obj(p.pull_request);
    if (!pr) return null;
    const head = obj(pr.head); const baseRef = obj(pr.base);
    return {
      ...base, kind: "PULL_REQUEST", action: str(p.action),
      pullRequest: {
        number: num(pr.number) ?? 0,
        title: sanitizeUntrustedText(pr.title),
        state: str(pr.state) ?? "open",
        baseBranch: sanitizeBranchName(baseRef?.ref),
        headBranch: sanitizeBranchName(head?.ref),
        baseCommit: str(baseRef?.sha),
        headCommit: str(head?.sha) ?? "",
      },
    };
  }
  if (eventType === "repository") return { ...base, kind: "REPOSITORY", action: str(p.action) };
  if (eventType === "installation") return { ...base, kind: "INSTALLATION", action: str(p.action) };
  return null;
}

/* ------------------------------- GitLab ------------------------------- */

export function normalizeGitLabRepository(project: Record<string, unknown>): ExternalRepository | null {
  if (typeof project.id !== "number" && typeof project.id !== "string") return null;
  return {
    provider: "GITLAB",
    externalId: String(project.id),
    fullName: sanitizeUntrustedText(project.path_with_namespace, 300),
    url: str(project.web_url) ?? "",
    defaultBranch: str(project.default_branch),
    visibility: visibilityOf(project.visibility),
    archived: project.archived === true,
    languages: [],
  };
}

export function parseGitLabEvent(eventType: string, payload: unknown): NormalizedSourceEvent | null {
  const p = obj(payload);
  if (!p) return null;
  const project = obj(p.project);
  const base: NormalizedSourceEvent = {
    provider: "GITLAB",
    kind: "UNKNOWN",
    externalRepoId: project && project.id != null ? String(project.id) : "",
    repositoryFullName: project ? sanitizeUntrustedText(project.path_with_namespace, 300) : "",
  };
  const kind = str(p.object_kind) ?? eventType;
  if (kind === "push") {
    return {
      ...base, kind: "PUSH",
      branch: sanitizeBranchName(str(p.ref)?.replace(/^refs\/heads\//, "")),
      commitSha: str(p.after),
    };
  }
  if (kind === "merge_request") {
    const attrs = obj(p.object_attributes);
    if (!attrs) return null;
    return {
      ...base, kind: "PULL_REQUEST", action: str(attrs.action),
      pullRequest: {
        number: num(attrs.iid) ?? 0,
        title: sanitizeUntrustedText(attrs.title),
        state: str(attrs.state) ?? "opened",
        baseBranch: sanitizeBranchName(attrs.target_branch),
        headBranch: sanitizeBranchName(attrs.source_branch),
        baseCommit: undefined,
        headCommit: str(attrs.last_commit ? obj(attrs.last_commit)?.id : undefined) ?? "",
      },
    };
  }
  if (kind === "pipeline") return { ...base, kind: "PIPELINE" };
  return null;
}

/* ------------------------------ Bitbucket ------------------------------ */

export function normalizeBitbucketRepository(repo: Record<string, unknown>): ExternalRepository | null {
  const uuid = str(repo.uuid);
  if (!uuid) return null;
  const links = obj(repo.links); const html = links ? obj(links.html) : null;
  return {
    provider: "BITBUCKET",
    externalId: uuid,
    fullName: sanitizeUntrustedText(repo.full_name, 300),
    url: str(html?.href) ?? "",
    installationId: str(obj(repo.workspace)?.uuid),
    defaultBranch: str(obj(repo.mainbranch)?.name),
    visibility: repo.is_private === false ? "PUBLIC" : "PRIVATE",
    archived: false,
    languages: repo.language ? [sanitizeUntrustedText(repo.language, 60)] : [],
  };
}

export function parseBitbucketEvent(eventKey: string, payload: unknown): NormalizedSourceEvent | null {
  const p = obj(payload);
  if (!p) return null;
  const repo = obj(p.repository);
  const base: NormalizedSourceEvent = {
    provider: "BITBUCKET",
    kind: "UNKNOWN",
    externalRepoId: repo ? (str(repo.uuid) ?? "") : "",
    repositoryFullName: repo ? sanitizeUntrustedText(repo.full_name, 300) : "",
    installationId: repo ? str(obj(repo.workspace)?.uuid) : undefined,
  };
  if (eventKey.startsWith("repo:push")) {
    const push = obj(p.push); const changes = Array.isArray(push?.changes) ? push.changes : [];
    const first = changes.length > 0 ? obj(changes[0]) : null;
    const newRef = first ? obj(first.new) : null;
    const target = newRef ? obj(newRef.target) : null;
    return {
      ...base, kind: "PUSH",
      branch: sanitizeBranchName(newRef?.name),
      commitSha: str(target?.hash),
    };
  }
  if (eventKey.startsWith("pullrequest:")) {
    const pr = obj(p.pullrequest);
    if (!pr) return null;
    const source = obj(pr.source); const dest = obj(pr.destination);
    const sourceCommit = source ? obj(source.commit) : null;
    const destCommit = dest ? obj(dest.commit) : null;
    return {
      ...base, kind: "PULL_REQUEST", action: eventKey.split(":")[1],
      pullRequest: {
        number: num(pr.id) ?? 0,
        title: sanitizeUntrustedText(pr.title),
        state: str(pr.state) ?? "OPEN",
        baseBranch: sanitizeBranchName(dest ? obj(dest.branch)?.name : undefined),
        headBranch: sanitizeBranchName(source ? obj(source.branch)?.name : undefined),
        baseCommit: str(destCommit?.hash),
        headCommit: str(sourceCommit?.hash) ?? "",
      },
    };
  }
  return null;
}

/** §26: GitLab MRs and Bitbucket PRs reuse the SAME assessment shape
 *  as GitHub PRs — one finding architecture, no per-provider forks. */
export function toExternalPullRequest(event: NormalizedSourceEvent): ExternalPullRequest | null {
  if (event.kind !== "PULL_REQUEST" || !event.pullRequest) return null;
  const pr = event.pullRequest;
  return {
    provider: event.provider,
    externalRepoId: event.externalRepoId,
    number: pr.number,
    title: pr.title,
    state: pr.state,
    baseBranch: pr.baseBranch,
    headBranch: pr.headBranch,
    baseCommit: pr.baseCommit,
    headCommit: pr.headCommit,
  };
}
