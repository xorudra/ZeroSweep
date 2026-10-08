/**
 * Recorded provider payload fixtures (Prompt 24 verification). These
 * are synthetic payloads in the documented provider shapes — no live
 * provider was contacted, and the "hostile" strings are inert test
 * data exercising the §114/§115 hostile-input cases.
 */

export const FIXTURE_WEBHOOK_SECRET = "fixture-webhook-secret-for-tests-only";

export const githubPushPayload = {
  ref: "refs/heads/main",
  after: "9f2c1a4b8d3e5f60718293a4b5c6d7e8f9012345",
  repository: {
    id: 424242, full_name: "rudra/example-service", html_url: "https://github.com/rudra/example-service",
    default_branch: "main", private: true, archived: false, language: "TypeScript",
  },
  installation: { id: 777 },
};

export const githubPullRequestPayload = {
  action: "opened",
  pull_request: {
    number: 17,
    // §114 hostile title: markup, script-like text, terminal escapes
    // and command substitution — all inert data for the platform.
    title: "Fix <script>alert(1)</script> auth \u001b[31mred\u001b[0m $(rm -rf /) header",
    state: "open",
    base: { ref: "main", sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    head: { ref: "feature/auth; rm -rf /", sha: "9f2c1a4b8d3e5f60718293a4b5c6d7e8f9012345" },
  },
  repository: {
    id: 424242, full_name: "rudra/example-service", html_url: "https://github.com/rudra/example-service",
    default_branch: "main", private: true, archived: false, language: "TypeScript",
  },
  installation: { id: 777 },
};

export const gitlabPushPayload = {
  object_kind: "push",
  ref: "refs/heads/develop",
  after: "1234567890abcdef1234567890abcdef12345678",
  project: {
    id: 909, path_with_namespace: "rudra/example-service", web_url: "https://gitlab.example.com/rudra/example-service",
    default_branch: "main", visibility: "private", archived: false,
  },
};

export const gitlabMergeRequestPayload = {
  object_kind: "merge_request",
  object_attributes: {
    iid: 42, title: "Add payments endpoint", state: "opened", action: "open",
    target_branch: "main", source_branch: "feat/payments",
    last_commit: { id: "1234567890abcdef1234567890abcdef12345678" },
  },
  project: {
    id: 909, path_with_namespace: "rudra/example-service", web_url: "https://gitlab.example.com/rudra/example-service",
    default_branch: "main", visibility: "private", archived: false,
  },
};

export const bitbucketPullRequestPayload = {
  repository: {
    uuid: "{repo-uuid-1}", full_name: "rudra/example-service", is_private: true,
    workspace: { uuid: "{ws-uuid-1}" }, mainbranch: { name: "main" }, language: "typescript",
    links: { html: { href: "https://bitbucket.org/rudra/example-service" } },
  },
  pullrequest: {
    id: 7, title: "Upgrade dependencies", state: "OPEN",
    source: { branch: { name: "deps/upgrade" }, commit: { hash: "abcdef1234567890abcdef1234567890abcdef12" } },
    destination: { branch: { name: "main" }, commit: { hash: "0000000000000000000000000000000000000000" } },
  },
};

export const jiraIssuePayload = {
  id: "10001",
  key: "SEC-123",
  fields: {
    status: { name: "Done", statusCategory: { key: "done" } },
    assignee: { accountId: "5b10ac8d82e05b22cc7d4ef5" },
  },
};

export const jiraIssueInProgressPayload = {
  id: "10001",
  key: "SEC-123",
  fields: {
    status: { name: "In Progress", statusCategory: { key: "indeterminate" } },
    assignee: null,
  },
};
