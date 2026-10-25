import { describe, expect, it } from "vitest";
import {
  FIXTURE_WEBHOOK_SECRET,
  bitbucketPullRequestPayload,
  githubPullRequestPayload,
  githubPushPayload,
  gitlabMergeRequestPayload,
  gitlabPushPayload,
  jiraIssuePayload,
} from "./fixtures";
import {
  MAX_WEBHOOK_PAYLOAD_BYTES,
  checkPayloadSize,
  signOutboundPayload,
  verifyGitHubSignature,
  verifyGitLabToken,
  verifySlackSignature,
} from "./webhook-verify";
import { hmacSha256Hex } from "../identity/crypto";
import { parseBitbucketEvent, parseGitHubEvent, parseGitLabEvent } from "./providers";
import { sanitizeBranchName, sanitizeUntrustedText, scrubSecretPatterns } from "./sanitize";
import { evaluateGate, parseGateRules, prPresetToRules } from "./gate";
import { classifyAgainstBaseline } from "./baseline";
import {
  CircuitBreaker,
  MAX_DELIVERY_ATTEMPTS,
  createEventEnvelope,
  formatCef,
  formatLeef,
  nextRetryDelayMs,
  retryAfterDelayMs,
  shouldDeadLetter,
  toSiemEvent,
} from "./events";
import { buildJiraIssuePayload, detectTicketConflicts, mapJiraStatusToInternal } from "./tickets";
import { buildSlackFindingAlert, buildTeamsFindingAlert } from "./messaging";
import { buildSarifLog } from "./sarif";
import { checkClonePolicy, checkSymlinkEscape, validateSubmoduleUrl } from "./ingestion";
import { generateOAuthState, validateOAuthState, validateRedirectUri, verifyPkceChallenge } from "./oauth";
import { generatePkcePair } from "../identity/oidc";
import { randomBytes } from "node:crypto";
import { GitHubConnector, JiraConnector, SlackConnector } from "./connectors";
import type { GateRule } from "./gate";
import type { IntegrationTransport, SanitizedFindingView } from "./types";
import type { HostResolver } from "../validation/scope-revalidation";
import { validateWebhookDestination } from "../continuous/webhook";

const finding = (over: Partial<SanitizedFindingView> = {}): SanitizedFindingView => ({
  id: "f-1", title: "SQL injection in login", severity: "HIGH", status: "OPEN",
  lifecycleStatus: "NEW", verificationStatus: "UNVERIFIED", kevListed: false,
  isSecretFinding: false, filePath: "src/auth/login.ts", startLine: 42,
  remediation: "Use parameterized queries", zerosweepReference: "finding:f-1",
  ...over,
});

describe("inbound webhook verification (§15, §25, §111–§113)", () => {
  const body = JSON.stringify(githubPushPayload);
  it("accepts a valid GitHub signature (§111)", () => {
    const sig = `sha256=${hmacSha256Hex(FIXTURE_WEBHOOK_SECRET, body)}`;
    expect(verifyGitHubSignature({ rawBody: body, signatureHeader: sig, secret: FIXTURE_WEBHOOK_SECRET }).ok).toBe(true);
  });
  it("rejects an invalid GitHub signature (§112)", () => {
    const sig = `sha256=${hmacSha256Hex("wrong-secret", body)}`;
    const v = verifyGitHubSignature({ rawBody: body, signatureHeader: sig, secret: FIXTURE_WEBHOOK_SECRET });
    expect(v.ok).toBe(false);
    expect(v.reasonCode).toBe("SIGNATURE_INVALID");
  });
  it("rejects a tampered body even with a well-formed header", () => {
    const sig = `sha256=${hmacSha256Hex(FIXTURE_WEBHOOK_SECRET, body)}`;
    expect(verifyGitHubSignature({ rawBody: body + " ", signatureHeader: sig, secret: FIXTURE_WEBHOOK_SECRET }).ok).toBe(false);
  });
  it("rejects a missing GitHub signature", () => {
    expect(verifyGitHubSignature({ rawBody: body, secret: FIXTURE_WEBHOOK_SECRET }).reasonCode).toBe("SIGNATURE_MISSING");
  });
  it("accepts the correct GitLab token and rejects a wrong one (§113)", () => {
    expect(verifyGitLabToken({ tokenHeader: FIXTURE_WEBHOOK_SECRET, secret: FIXTURE_WEBHOOK_SECRET }).ok).toBe(true);
    const bad = verifyGitLabToken({ tokenHeader: "not-the-secret", secret: FIXTURE_WEBHOOK_SECRET });
    expect(bad.ok).toBe(false);
    expect(bad.reasonCode).toBe("TOKEN_INVALID");
  });
  it("enforces the payload size cap before parsing (§82)", () => {
    expect(checkPayloadSize("x".repeat(MAX_WEBHOOK_PAYLOAD_BYTES + 1))?.reasonCode).toBe("PAYLOAD_TOO_LARGE");
    expect(checkPayloadSize("{}")).toBeNull();
  });
  it("verifies Slack signatures with a bounded timestamp skew (§57, §100)", () => {
    const ts = "1700000000";
    const raw = "payload=%7B%7D";
    const sig = `v0=${hmacSha256Hex(FIXTURE_WEBHOOK_SECRET, `v0:${ts}:${raw}`)}`;
    expect(verifySlackSignature({ rawBody: raw, signatureHeader: sig, timestampHeader: ts, secret: FIXTURE_WEBHOOK_SECRET, nowSeconds: 1700000100 }).ok).toBe(true);
    expect(verifySlackSignature({ rawBody: raw, signatureHeader: sig, timestampHeader: ts, secret: FIXTURE_WEBHOOK_SECRET, nowSeconds: 1700001000 }).reasonCode).toBe("TIMESTAMP_SKEW");
  });
  it("signs outbound payloads with an HMAC the receiver can verify (§71)", () => {
    const raw = JSON.stringify({ event: "finding.created" });
    const header = signOutboundPayload(FIXTURE_WEBHOOK_SECRET, raw);
    expect(header).toBe(`sha256=${hmacSha256Hex(FIXTURE_WEBHOOK_SECRET, raw)}`);
  });
});

describe("provider payload normalization (§14, §23, §27)", () => {
  it("normalizes a GitHub push event", () => {
    const e = parseGitHubEvent("push", githubPushPayload);
    expect(e?.kind).toBe("PUSH");
    expect(e?.externalRepoId).toBe("424242");
    expect(e?.branch).toBe("main");
    expect(e?.installationId).toBe("777");
  });
  it("normalizes GitLab push and merge-request events onto the same shape", () => {
    expect(parseGitLabEvent("push", gitlabPushPayload)?.kind).toBe("PUSH");
    const mr = parseGitLabEvent("merge_request", gitlabMergeRequestPayload);
    expect(mr?.kind).toBe("PULL_REQUEST");
    expect(mr?.pullRequest?.number).toBe(42);
    expect(mr?.pullRequest?.headCommit).toBe("1234567890abcdef1234567890abcdef12345678");
  });
  it("normalizes a Bitbucket pull-request event", () => {
    const pr = parseBitbucketEvent("pullrequest:created", bitbucketPullRequestPayload);
    expect(pr?.kind).toBe("PULL_REQUEST");
    expect(pr?.pullRequest?.number).toBe(7);
    expect(pr?.pullRequest?.baseBranch).toBe("main");
  });
  it("returns null for malformed payloads instead of throwing", () => {
    expect(parseGitHubEvent("push", "not-an-object")).toBeNull();
    expect(parseGitLabEvent("merge_request", {})).toBeNull();
  });
});

describe("hostile provider text (§83, §114, §115)", () => {
  it("strips terminal escapes from a hostile PR title while keeping it inert data (§114)", () => {
    const e = parseGitHubEvent("pull_request", githubPullRequestPayload);
    const title = e?.pullRequest?.title ?? "";
    expect(title).not.toContain("\u001b");
    expect(title).toContain("<script>alert(1)</script>"); // stored as inert text, rendered escaped by UI
    expect(title).toContain("$(rm -rf /)"); // data — never executed anywhere
  });
  it("treats a shell-metacharacter branch name as data (§115)", () => {
    const e = parseGitHubEvent("pull_request", githubPullRequestPayload);
    expect(e?.pullRequest?.headBranch).toBe("feature/auth; rm -rf /");
    expect(sanitizeBranchName("main`whoami`")).toBe("main`whoami`");
  });
  it("caps hostile over-length values", () => {
    expect(sanitizeUntrustedText("a".repeat(5000)).length).toBe(500);
  });
});

describe("quality gate engine (§36–§39, §120, §123)", () => {
  it("fails when a PR introduces a critical finding under FAIL_ON_NEW_CRITICAL (§120)", () => {
    const gate = evaluateGate(
      { newFindings: [{ severity: "CRITICAL", verificationStatus: "UNVERIFIED", kevListed: false, isSecretFinding: false }], coveragePercent: 100, scannerResults: [] },
      { rules: prPresetToRules("FAIL_ON_NEW_CRITICAL"), scannerFailureBehavior: "FAIL_CLOSED" },
    );
    expect(gate.result).toBe("FAIL");
    expect(gate.summary.newCritical).toBe(1);
  });
  it("passes a clean PR", () => {
    const gate = evaluateGate(
      { newFindings: [], coveragePercent: 95, scannerResults: [{ scanner: "semgrep", status: "COMPLETED" }] },
      { rules: [...prPresetToRules("FAIL_ON_NEW_HIGH"), { kind: "minimumScanCoverage", minimumPercent: 80 }, { kind: "requiredScanners", scanners: ["semgrep"] }], scannerFailureBehavior: "FAIL_CLOSED" },
    );
    expect(gate.result).toBe("PASS");
  });
  it("applies the configured scanner-failure behavior (§123)", () => {
    const input = {
      newFindings: [],
      coveragePercent: 100,
      scannerResults: [{ scanner: "semgrep", status: "FAILED" as const }],
    };
    const rules: GateRule[] = [{ kind: "requiredScanners", scanners: ["semgrep"] }];
    expect(evaluateGate(input, { rules, scannerFailureBehavior: "FAIL_CLOSED" }).result).toBe("FAIL");
    expect(evaluateGate(input, { rules, scannerFailureBehavior: "WARN" }).result).toBe("WARN");
    expect(evaluateGate(input, { rules, scannerFailureBehavior: "FAIL_OPEN" }).result).toBe("PASS");
  });
  it("blocks KEV, secret and verified-critical presets", () => {
    const base = { coveragePercent: 100, scannerResults: [] };
    expect(evaluateGate({ ...base, newFindings: [{ severity: "HIGH", verificationStatus: "UNVERIFIED", kevListed: true, isSecretFinding: false }] }, { rules: prPresetToRules("FAIL_ON_NEW_KEV"), scannerFailureBehavior: "FAIL_CLOSED" }).result).toBe("FAIL");
    expect(evaluateGate({ ...base, newFindings: [{ severity: "HIGH", verificationStatus: "UNVERIFIED", kevListed: false, isSecretFinding: true }] }, { rules: prPresetToRules("FAIL_ON_NEW_SECRET"), scannerFailureBehavior: "FAIL_CLOSED" }).result).toBe("FAIL");
    expect(evaluateGate({ ...base, newFindings: [{ severity: "HIGH", verificationStatus: "CONFIRMED", kevListed: false, isSecretFinding: false }] }, { rules: prPresetToRules("FAIL_ON_NEW_VERIFIED_HIGH"), scannerFailureBehavior: "FAIL_CLOSED" }).result).toBe("FAIL");
    // unverified high does NOT trip the verified-high preset
    expect(evaluateGate({ ...base, newFindings: [{ severity: "HIGH", verificationStatus: "UNVERIFIED", kevListed: false, isSecretFinding: false }] }, { rules: prPresetToRules("FAIL_ON_NEW_VERIFIED_HIGH"), scannerFailureBehavior: "FAIL_CLOSED" }).result).toBe("PASS");
  });
  it("rejects unknown rule kinds in untrusted policy input (§38)", () => {
    const parsed = parseGateRules([{ kind: "eval", code: "process.exit()" }, { kind: "maxNewCritical", max: 0 }]);
    expect(parsed.ok).toBe(false);
    expect(parsed.rules).toHaveLength(1);
  });
  it("returns SKIPPED for a policy with no rules", () => {
    expect(evaluateGate({ newFindings: [], coveragePercent: null, scannerResults: [] }, { rules: [], scannerFailureBehavior: "FAIL_CLOSED" }).result).toBe("SKIPPED");
  });
});

describe("baseline classification (§40, §121, §122)", () => {
  it("never classifies a pre-existing finding as NEW (§121)", () => {
    const r = classifyAgainstBaseline({
      baselineFingerprints: ["fp-high-old"],
      currentFingerprints: ["fp-high-old"],
    });
    expect(r.perFinding).toEqual([{ fingerprint: "fp-high-old", classification: "PRE_EXISTING" }]);
    expect(r.newFingerprints).toEqual([]);
  });
  it("classifies a reappearing resolved fingerprint as REGRESSED (§122)", () => {
    const r = classifyAgainstBaseline({
      baselineFingerprints: ["fp-a"],
      currentFingerprints: ["fp-a", "fp-b"],
      previouslyResolvedFingerprints: ["fp-b"],
    });
    expect(r.regressedFingerprints).toEqual(["fp-b"]);
    expect(r.newFingerprints).toEqual([]);
  });
  it("reports baseline fingerprints absent now as resolved", () => {
    const r = classifyAgainstBaseline({ baselineFingerprints: ["fp-a", "fp-gone"], currentFingerprints: ["fp-a", "fp-new"] });
    expect(r.resolvedFingerprints).toEqual(["fp-gone"]);
    expect(r.newFingerprints).toEqual(["fp-new"]);
  });
});

describe("ticket sync (§50–§54, §125, §126)", () => {
  it("maps Jira statuses onto the ticket vocabulary (§51, §125)", () => {
    expect(mapJiraStatusToInternal({ statusName: "Done", statusCategory: "done" })).toBe("CLOSED");
    expect(mapJiraStatusToInternal({ statusName: "Resolved", statusCategory: "done" })).toBe("RESOLVED");
    expect(mapJiraStatusToInternal({ statusName: "In Progress", statusCategory: "indeterminate" })).toBe("IN_PROGRESS");
    expect(mapJiraStatusToInternal({ statusName: "To Do", statusCategory: "new" })).toBe("OPEN");
    const fields = (jiraIssuePayload as { fields: { status: { name: string; statusCategory: { key: string } } } }).fields;
    expect(mapJiraStatusToInternal({ statusName: fields.status.name, statusCategory: fields.status.statusCategory.key })).toBe("CLOSED");
  });
  it("builds a sanitized Jira payload with no secret values (§50)", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const { payload, redactions } = buildJiraIssuePayload(
      finding({ remediation: `Rotate the key ${secret} immediately`, title: `Leaked key ${secret}` }),
      { projectKey: "SEC", issueType: "Task" },
    );
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain(secret);
    expect(serialized).toContain("[REDACTED]");
    expect(redactions.length).toBeGreaterThan(0);
  });
  it("detects a two-sided status conflict and never picks a winner (§126)", () => {
    const r = detectTicketConflicts({
      local: { status: "IN_PROGRESS" },
      external: { status: "CLOSED" },
      lastSynced: { status: "OPEN" },
    });
    expect(r.conflicts).toEqual([{ field: "status", localValue: "IN_PROGRESS", externalValue: "CLOSED" }]);
  });
  it("one-sided changes are not conflicts", () => {
    const r = detectTicketConflicts({
      local: { status: "OPEN" },
      external: { status: "IN_PROGRESS" },
      lastSynced: { status: "OPEN" },
    });
    expect(r.conflicts).toEqual([]);
    expect(r.externalChanged).toBe(true);
  });
});

describe("messaging redaction (§56, §119, §127)", () => {
  it("never puts a synthetic secret into a Slack alert (§127)", () => {
    const secret = "xoxb-123456789012-abcdefghijkl";
    const payload = buildSlackFindingAlert(finding({ title: `Token ${secret} exposed`, remediation: `Revoke ${secret}` }));
    expect(JSON.stringify(payload)).not.toContain(secret);
    expect(JSON.stringify(payload)).toContain("[REDACTED]");
  });
  it("never puts a secret into a Teams card", () => {
    const secret = "ghp_1234567890abcdefghijklmnopqrstuv";
    const payload = buildTeamsFindingAlert(finding({ title: `Key ${secret}` }));
    expect(JSON.stringify(payload)).not.toContain(secret);
  });
  it("scrubs credential assignments and private keys", () => {
    const { text } = scrubSecretPatterns("password = hunter2hunter2 and -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----");
    expect(text).not.toContain("hunter2hunter2");
    expect(text).not.toContain("BEGIN PRIVATE KEY");
  });
});

describe("SARIF export (§43–§45, §119)", () => {
  it("produces SARIF 2.1.0 with redacted messages and repo-relative locations", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const { sarif } = buildSarifLog({
      toolName: "ZeroSweep",
      findings: [{ ...finding({ title: `AWS key ${secret} in config` }), ruleId: "secrets/aws-key", cwe: "CWE-798" }],
    });
    const s = sarif as { version: string; runs: Array<{ results: Array<{ level: string; locations: unknown[] }> }> };
    expect(s.version).toBe("2.1.0");
    expect(s.runs[0]!.results[0]!.level).toBe("error");
    expect(JSON.stringify(sarif)).not.toContain(secret);
    expect(JSON.stringify(sarif)).toContain("[REDACTED]");
  });
});

describe("event bus, SIEM and delivery reliability (§62–§80, §130–§132)", () => {
  it("creates versioned envelopes with stable ids (§76, §77)", () => {
    const env = createEventEnvelope({ eventType: "finding.created", workspaceId: "ws-1", resourceType: "Finding", resourceId: "f-1", payload: { severity: "HIGH" }, eventId: "evt-stable-1" });
    expect(env.eventId).toBe("evt-stable-1");
    expect(env.schemaVersion).toBe("1.0");
  });
  it("maps events to SIEM JSON/CEF/LEEF without secrets (§63, §64)", () => {
    const ev = toSiemEvent({
      eventId: "evt-1", timestamp: "2026-10-08T00:00:00.000Z", workspaceId: "ws-1",
      eventType: "CRITICAL_FINDING", severity: "CRITICAL", status: "OPEN",
      findingId: "f-1", riskScore: 9.1, cve: "CVE-2021-44228", cwe: "CWE-89",
    });
    expect(formatCef(ev)).toContain("CEF:0|ZeroSweep|ZeroSweep|1.0|CRITICAL_FINDING|");
    expect(formatCef(ev)).toContain("externalId=evt-1");
    expect(formatLeef(ev)).toContain("LEEF:2.0|ZeroSweep|");
    expect(JSON.stringify(ev)).not.toContain("secret");
  });
  it("bounds retries and dead-letters (§72, §131)", () => {
    expect(nextRetryDelayMs(1)).toBe(30_000);
    expect(nextRetryDelayMs(2)).toBeGreaterThan(nextRetryDelayMs(1));
    expect(shouldDeadLetter(MAX_DELIVERY_ATTEMPTS)).toBe(true);
    expect(shouldDeadLetter(MAX_DELIVERY_ATTEMPTS - 1)).toBe(false);
  });
  it("opens the circuit breaker after repeated failures (§96)", () => {
    const breaker = new CircuitBreaker(3, 60_000);
    const t0 = 1_000_000;
    breaker.recordFailure(t0); breaker.recordFailure(t0); breaker.recordFailure(t0);
    expect(breaker.state(t0)).toBe("OPEN");
    expect(breaker.canExecute(t0)).toBe(false);
    expect(breaker.canExecute(t0 + 61_000)).toBe(true); // half-open probe
    breaker.recordSuccess();
    expect(breaker.state(t0)).toBe("CLOSED");
  });
  it("honors Retry-After with a cap (§97, §132)", () => {
    expect(retryAfterDelayMs({ "retry-after": "30" }, 0)).toBe(30_000);
    expect(retryAfterDelayMs({ "retry-after": "99999" }, 0)).toBe(3_600_000);
    expect(retryAfterDelayMs({}, 0)).toBeNull();
  });
});

describe("repository ingestion safety (§85–§89, §117, §118)", () => {
  it("blocks SSRF submodule URLs (§117)", () => {
    expect(validateSubmoduleUrl("https://169.254.169.254.evil.example/x.git", { allowedHosts: ["github.com"] }).ok).toBe(false);
    expect(validateSubmoduleUrl("http://github.com/a/b.git", { allowedHosts: ["github.com"] }).ok).toBe(false); // http
    expect(validateSubmoduleUrl("https://unlisted.example.com/a/b.git", { allowedHosts: ["github.com"] }).ok).toBe(false);
    expect(validateSubmoduleUrl("https://github.com/a/b.git", { allowedHosts: ["github.com"] }).ok).toBe(true);
  });
  it("blocks symlinks escaping the checkout (§118)", () => {
    const r = checkSymlinkEscape([
      { path: "src/link", linkTarget: "../../etc/passwd" },
      { path: "src/ok", linkTarget: "./real-file" },
      { path: "abs", linkTarget: "/etc/passwd" },
    ]);
    expect(r.ok).toBe(false);
    expect(r.violations.map((v) => v.path)).toEqual(["src/link", "abs"]);
    expect(checkSymlinkEscape([{ path: "a/b", linkTarget: "../c" }]).ok).toBe(true);
  });
  it("enforces clone budgets and archive-bomb ratios (§87, §88)", () => {
    expect(checkClonePolicy({ sizeBytes: 3 * 1024 * 1024 * 1024 }).ok).toBe(false);
    expect(checkClonePolicy({ compressedBytes: 1_000, decompressedBytes: 1_000_000 }).ok).toBe(false);
    expect(checkClonePolicy({ sizeBytes: 10_000, fileCount: 100 }).ok).toBe(true);
  });
});

describe("OAuth connection safety (§101, §102)", () => {
  it("validates state in constant time and PKCE S256", () => {
    const state = generateOAuthState();
    expect(validateOAuthState(state, state)).toBe(true);
    expect(validateOAuthState(state, generateOAuthState())).toBe(false);
    const pkce = generatePkcePair(randomBytes(32));
    expect(verifyPkceChallenge(pkce.verifier, pkce.challenge)).toBe(true);
    expect(verifyPkceChallenge("wrong-verifier", pkce.challenge)).toBe(false);
  });
  it("requires exact redirect URI matches (§101)", () => {
    const registered = ["https://app.example.com/oauth/callback"];
    expect(validateRedirectUri("https://app.example.com/oauth/callback", registered)).toBe(true);
    expect(validateRedirectUri("https://app.example.com/oauth/callback.evil.com", registered)).toBe(false);
    expect(validateRedirectUri("https://app.example.com/oauth/callback?next=//evil", registered)).toBe(false);
  });
});

describe("connectors (§6, §10, §46, §55)", () => {
  const fixtureTransport = (handler: (path: string) => { status: number; body: unknown }): IntegrationTransport => ({
    request: async ({ path }) => handler(path),
  });

  it("honestly reports NOT_CONFIGURED without a transport", async () => {
    const gh = new GitHubConnector({ authMode: "GITHUB_APP", appId: "123", installationId: "777", privateKeySecretReference: "gh-app-key" });
    const health = await gh.healthCheck();
    expect(health.status).toBe("NOT_CONFIGURED");
    expect(gh.capabilities()).toContain("checks.write");
  });

  it("validates GitHub App configuration (§11)", () => {
    const gh = new GitHubConnector({});
    expect(gh.validateConfiguration({ authMode: "GITHUB_APP" }).ok).toBe(false);
    expect(gh.validateConfiguration({ authMode: "GITHUB_APP", appId: "1", installationId: "2", privateKeySecretReference: "ref" }).ok).toBe(true);
  });

  it("syncs repositories through a fixture transport (§13)", async () => {
    const gh = new GitHubConnector(
      { authMode: "GITHUB_APP", appId: "1", installationId: "2", privateKeySecretReference: "ref" },
      fixtureTransport((path) => path === "/installation/repositories"
        ? { status: 200, body: { repositories: [githubPushPayload.repository] } }
        : { status: 200, body: { resources: { core: { remaining: 4999, reset: 1700000000 } } } }),
    );
    const { repositories } = await gh.listRepositories();
    expect(repositories[0]?.externalId).toBe("424242");
    expect(repositories[0]?.fullName).toBe("rudra/example-service");
    const health = await gh.healthCheck();
    expect(health.status).toBe("CONNECTED");
    expect(health.rateLimit?.remaining).toBe(4999);
  });

  it("creates Jira issues through a fixture transport from a sanitized payload (§46)", async () => {
    const jira = new JiraConnector(
      { baseUrl: "https://example.atlassian.net", credentialSecretReference: "jira-token" },
      fixtureTransport(() => ({ status: 201, body: { id: "10001", key: "SEC-123" } })),
    );
    const created = await jira.createIssue(finding(), { projectKey: "SEC", issueType: "Task" });
    expect(created).toEqual({ externalId: "10001", externalKey: "SEC-123" });
  });

  it("records Slack delivery as NOT_CONFIGURED instead of claiming success (§59)", async () => {
    const slack = new SlackConnector({ channel: "#security" });
    const sent = await slack.sendFindingAlert(finding());
    expect(sent.delivered).toBe(false);
    expect(sent.detail).toContain("NOT_CONFIGURED");
  });
});

describe("outbound webhook destination validation (§70, §128)", () => {
  const resolver: HostResolver = async (host) => {
    if (host === "hooks.example.com") return ["93.184.216.34"];
    if (host === "metadata.example.com") return ["169.254.169.254"];
    if (host === "priv.example.com") return ["10.0.0.5"];
    return [];
  };
  it("blocks loopback, metadata and private destinations after DNS resolution (§128)", async () => {
    for (const url of ["https://127.0.0.1/hook", "https://localhost/hook", "https://metadata.example.com/hook", "https://priv.example.com/hook"]) {
      const v = await validateWebhookDestination({ url, allowlist: ["*.example.com"], resolver });
      expect(v.ok, url).toBe(false);
    }
    const ok = await validateWebhookDestination({ url: "https://hooks.example.com/hook", allowlist: ["*.example.com"], resolver });
    expect(ok.ok).toBe(true);
  });
});
