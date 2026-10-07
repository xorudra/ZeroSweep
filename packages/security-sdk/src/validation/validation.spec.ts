import { describe, expect, it } from "vitest";
import {
  ADMIN_HARD_LIMITS,
  DEFAULT_VALIDATION_BUDGET,
} from "./types";
import {
  classifyTechnique,
  getValidator,
  isProhibitedTechnique,
  validatorsForFinding,
} from "./catalog";
import {
  buildValidationPlan,
  containsShellMetachars,
  hashValidationPlan,
  validateValidatorParameters,
  ValidationPlanError,
} from "./plan";
import {
  DEFAULT_ORGANIZATION_VALIDATION_POLICY,
  evaluateValidationPolicy,
  type ValidationPolicyInput,
} from "./policy";
import {
  BudgetExceededError,
  clampValidationBudget,
  ValidationBudgetTracker,
  ValidationRateLimiter,
} from "./budget";
import {
  buildValidationEvidence,
  sanitizeEvidenceText,
  sanitizeEvidenceValue,
} from "./evidence";
import { revalidateScope } from "./scope-revalidation";
import { activeKillSwitch } from "./kill-switch";
import { hashCallbackToken, issueCallbackToken, verifyCallbackToken } from "./callback";
import {
  confidenceUpdateForManualValidation,
  confidenceUpdateForOutcome,
} from "./confidence";
import {
  budgetedTransport,
  FixtureValidationTransport,
  getValidatorImplementation,
} from "./validators";
import {
  AD_FINDING,
  CLOUD_FINDING,
  CONTAINER_FINDING,
  FIXED_HEADER_FINDING,
  FIXTURE_SCOPE_RULES,
  HEADER_FINDING,
  K8S_FINDING,
  SERVICE_FINDING,
  SOURCE_FINDING,
  SQLI_FINDING,
  TLS_FINDING,
  XSS_FINDING,
} from "./fixtures";
import type { ScopeRules } from "@dsrclone/validation";

const scopeRules = FIXTURE_SCOPE_RULES as ScopeRules;
const NOW = new Date("2026-10-07T12:00:00.000Z");

function policyInput(overrides: Partial<ValidationPolicyInput> = {}): ValidationPolicyInput {
  return {
    policy: { ...DEFAULT_ORGANIZATION_VALIDATION_POLICY },
    environment: "PRODUCTION",
    authorization: { targetVerified: true, assessmentApproved: true },
    scope: { inScope: true },
    technique: "header-recheck",
    riskClass: "SAFE",
    requestedBy: "user-requester",
    planHash: "hash-1",
    targetId: "target-1",
    findingId: "finding-1",
    now: NOW,
    ...overrides,
  };
}

function validApproval(overrides: Record<string, unknown> = {}) {
  return {
    approverId: "user-approver",
    decision: "APPROVED",
    planHash: "hash-1",
    targetId: "target-1",
    findingId: "finding-1",
    validatorSlug: "header-recheck",
    expiresAt: "2026-10-07T13:00:00.000Z",
    ...overrides,
  };
}

async function runValidator(slug: string, finding: typeof HEADER_FINDING, parameters: Record<string, string | number | boolean> = {}) {
  const impl = getValidatorImplementation(slug);
  if (!impl) throw new Error(`no implementation for ${slug}`);
  const budget = new ValidationBudgetTracker(DEFAULT_VALIDATION_BUDGET);
  const transport = budgetedTransport(new FixtureValidationTransport(), budget);
  const ctx = { finding, parameters, transport, budget };
  await impl.prepare(ctx);
  const result = await impl.execute(ctx);
  await impl.cleanup(ctx);
  return { result, evidence: impl.parseEvidence(result).map((e) => buildValidationEvidence(e)) };
}

describe("validator catalog (§6/§14/§68)", () => {
  it("every catalog validator has an implementation and vice versa", () => {
    for (const slug of ["header-recheck", "tls-recheck", "endpoint-exposure-recheck", "nuclei-recheck", "service-presence-recheck", "api-safe-recheck", "cloud-config-recheck", "kubernetes-posture-recheck", "source-recheck", "container-image-recheck", "ad-posture-recheck"]) {
      expect(getValidator(slug), slug).toBeDefined();
      expect(getValidatorImplementation(slug), slug).toBeDefined();
    }
  });

  it("routes findings to their safe validators", () => {
    expect(validatorsForFinding(HEADER_FINDING).map((v) => v.slug)).toContain("header-recheck");
    expect(validatorsForFinding(TLS_FINDING).map((v) => v.slug)).toContain("tls-recheck");
    expect(validatorsForFinding(CLOUD_FINDING).map((v) => v.slug)).toContain("cloud-config-recheck");
    expect(validatorsForFinding(K8S_FINDING).map((v) => v.slug)).toContain("kubernetes-posture-recheck");
    expect(validatorsForFinding(AD_FINDING).map((v) => v.slug)).toContain("ad-posture-recheck");
    expect(validatorsForFinding(CONTAINER_FINDING).map((v) => v.slug)).toContain("container-image-recheck");
    expect(validatorsForFinding(SOURCE_FINDING).map((v) => v.slug)).toContain("source-recheck");
  });

  it("SQLi/XSS findings validate ONLY via the scanner-evidence recheck (§16/§17)", () => {
    const sqliValidators = validatorsForFinding(SQLI_FINDING).map((v) => v.slug);
    expect(sqliValidators).toContain("nuclei-recheck");
    // No validator offers data extraction or script execution — the
    // catalog simply contains nothing else applicable.
    expect(sqliValidators).not.toContain("header-recheck");
    expect(validatorsForFinding(XSS_FINDING).map((v) => v.slug)).toContain("nuclei-recheck");
  });
});

describe("prohibited automation (§95/§97)", () => {
  it.each([
    "credential dumping", "password spraying", "credential stuffing", "NTLM relay",
    "Kerberoasting", "AS-REP roasting", "DCSync", "ticket forging", "lateral movement",
    "privilege escalation", "persistence", "database dumping", "remote command execution",
    "NTLM poisoning", "account lockout testing", "container escape", "malware deployment",
  ])("classifies %s as PROHIBITED_AUTOMATION", (name) => {
    expect(classifyTechnique(name)).toBe("PROHIBITED_AUTOMATION");
    expect(isProhibitedTechnique(name)).toBe(true);
  });

  it("policy DENIES prohibited techniques even with an approval in a LAB", () => {
    const d = evaluateValidationPolicy(policyInput({
      technique: "password-spraying",
      riskClass: "PROHIBITED_AUTOMATION",
      environment: "LAB",
      approval: validApproval({ validatorSlug: "password-spraying" }),
    }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("PROHIBITED_AUTOMATION");
  });

  it("command-injection validation is prohibited automation (§20)", () => {
    expect(classifyTechnique("os-command-execution")).toBe("PROHIBITED_AUTOMATION");
    const d = evaluateValidationPolicy(policyInput({ technique: "remote-command-execution", riskClass: "PROHIBITED_AUTOMATION" }));
    expect(d.decision).toBe("DENY");
  });

  it("RCE validation is never automated (§21) — INTRUSIVE is denied in production", () => {
    const d = evaluateValidationPolicy(policyInput({ technique: "some-intrusive-check", riskClass: "INTRUSIVE", approval: validApproval({ validatorSlug: "some-intrusive-check" }) }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("INTRUSIVE_NOT_AUTOMATED");
  });
});

describe("ValidationPolicyEngine (§7)", () => {
  it("ALLOWs a SAFE validation on a verified target with an approved assessment in scope", () => {
    expect(evaluateValidationPolicy(policyInput()).decision).toBe("ALLOW");
  });

  it("DENIES when the target is not verified or the assessment is not approved", () => {
    expect(evaluateValidationPolicy(policyInput({ authorization: { targetVerified: false, assessmentApproved: true } })).reasonCode).toBe("TARGET_NOT_VERIFIED");
    expect(evaluateValidationPolicy(policyInput({ authorization: { targetVerified: true, assessmentApproved: false } })).reasonCode).toBe("ASSESSMENT_NOT_APPROVED");
  });

  it("DENIES when the authorization snapshot has expired (§8)", () => {
    const d = evaluateValidationPolicy(policyInput({ authorization: { targetVerified: true, assessmentApproved: true, expiresAt: "2026-10-07T11:00:00.000Z" } }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("AUTHORIZATION_EXPIRED");
  });

  it("DENIES out-of-scope validations (§85)", () => {
    const d = evaluateValidationPolicy(policyInput({ scope: { inScope: false, reason: "outside scope" } }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("OUT_OF_SCOPE");
  });

  it("§92: REVIEW_REQUIRED without approval → REQUIRE_APPROVAL; with valid approval → ALLOW", () => {
    const noApproval = evaluateValidationPolicy(policyInput({ riskClass: "REVIEW_REQUIRED", technique: "nuclei-recheck", approval: null }));
    expect(noApproval.decision).toBe("REQUIRE_APPROVAL");
    const withApproval = evaluateValidationPolicy(policyInput({
      riskClass: "REVIEW_REQUIRED", technique: "nuclei-recheck",
      approval: validApproval({ validatorSlug: "nuclei-recheck" }),
    }));
    expect(withApproval.decision).toBe("ALLOW");
    expect(withApproval.reasonCode).toBe("APPROVED");
  });

  it("§93: expired approval → DENIED", () => {
    const d = evaluateValidationPolicy(policyInput({
      riskClass: "REVIEW_REQUIRED", technique: "nuclei-recheck",
      approval: validApproval({ validatorSlug: "nuclei-recheck", expiresAt: "2026-10-07T11:59:00.000Z" }),
    }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("APPROVAL_EXPIRED");
  });

  it("plan-hash mismatch voids the approval (§10)", () => {
    const d = evaluateValidationPolicy(policyInput({
      riskClass: "REVIEW_REQUIRED", technique: "nuclei-recheck",
      approval: validApproval({ validatorSlug: "nuclei-recheck", planHash: "hash-OTHER" }),
    }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("APPROVAL_PLAN_MISMATCH");
  });

  it("separation of duties: requester cannot self-approve higher-risk validation (§11)", () => {
    const d = evaluateValidationPolicy(policyInput({
      riskClass: "REVIEW_REQUIRED", technique: "nuclei-recheck",
      approval: validApproval({ validatorSlug: "nuclei-recheck", approverId: "user-requester" }),
    }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("SEPARATION_OF_DUTIES");
  });

  it("production SAFE_ONLY: LOW_IMPACT requires approval (§64); high criticality too (§66)", () => {
    expect(evaluateValidationPolicy(policyInput({ riskClass: "LOW_IMPACT" })).decision).toBe("REQUIRE_APPROVAL");
    const critical = evaluateValidationPolicy(policyInput({ riskClass: "LOW_IMPACT", assetCriticality: "CRITICAL" }));
    expect(critical.decision).toBe("REQUIRE_APPROVAL");
    expect(critical.reasonCode).toBe("CRITICALITY_REQUIRES_APPROVAL");
  });

  it("workspace validator allowlist is enforced (§77)", () => {
    const d = evaluateValidationPolicy(policyInput({
      policy: { ...DEFAULT_ORGANIZATION_VALIDATION_POLICY, allowedValidators: ["tls-recheck"] },
    }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("VALIDATOR_NOT_ALLOWED");
  });

  it("LAB is an explicit marker, never inferred (§65): LAB alone does not allow INTRUSIVE without the §63 architecture", () => {
    const d = evaluateValidationPolicy(policyInput({ technique: "x", riskClass: "INTRUSIVE", environment: "LAB" }));
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("INTRUSIVE_NOT_AUTOMATED");
  });
});

describe("validation plans (§13/§79/§90)", () => {
  it("builds a fixed-DAG plan and a stable content hash", () => {
    const { plan, planHash } = buildValidationPlan({ validatorSlug: "header-recheck", finding: HEADER_FINDING, targetId: "target-1", budget: DEFAULT_VALIDATION_BUDGET });
    expect(plan.stages).toEqual(["AUTHORIZATION", "SCOPE_REVALIDATION", "POLICY", "APPROVAL", "BUDGET", "SAFE_VALIDATOR", "EVIDENCE", "CONFIDENCE_UPDATE", "REPORT"]);
    const again = buildValidationPlan({ validatorSlug: "header-recheck", finding: HEADER_FINDING, targetId: "target-1", budget: DEFAULT_VALIDATION_BUDGET });
    expect(again.planHash).toBe(planHash);
    expect(hashValidationPlan(plan)).toBe(planHash);
  });

  it("any plan change changes the hash — approvals void on edit (§10)", () => {
    const a = buildValidationPlan({ validatorSlug: "header-recheck", finding: HEADER_FINDING, targetId: "target-1", budget: DEFAULT_VALIDATION_BUDGET });
    const b = buildValidationPlan({ validatorSlug: "header-recheck", finding: HEADER_FINDING, targetId: "target-1", parameters: { headerName: "X-Frame-Options" }, budget: DEFAULT_VALIDATION_BUDGET });
    expect(b.planHash).not.toBe(a.planHash);
  });

  it("§79: forbidden fields are rejected — command/payload/script/args/raw template", () => {
    for (const bad of [{ command: "id" }, { payload: "x" }, { script: "x" }, { args: ["-sV"] }, { template: "id: x" }]) {
      expect(() => buildValidationPlan({ validatorSlug: "header-recheck", finding: HEADER_FINDING, targetId: "t", parameters: bad, budget: DEFAULT_VALIDATION_BUDGET })).toThrow(ValidationPlanError);
    }
  });

  it("§90: shell metacharacters in configuration values are rejected as data", () => {
    for (const evil of ["a;id", "a&&id", "a$(id)", "a`id`", "a\nid", "a|id"]) {
      expect(containsShellMetachars(evil)).toBe(true);
      expect(() => validateValidatorParameters("header-recheck", { headerName: evil })).toThrow(/metacharacters/);
    }
    expect(() => validateValidatorParameters("header-recheck", { undeclared: "x" })).toThrow(/allowlisted/);
  });

  it("unsupported finding/validator pairs cannot be planned", () => {
    expect(() => buildValidationPlan({ validatorSlug: "cloud-config-recheck", finding: HEADER_FINDING, targetId: "t", budget: DEFAULT_VALIDATION_BUDGET })).toThrow(/does not support/);
  });
});

describe("budgets & rate limits (§40–§42/§88)", () => {
  it("clamps every dimension to administrator hard limits (§41)", () => {
    const clamped = clampValidationBudget({ maxRequests: 100_000, maxDurationSeconds: 99_999, maxBytes: 10 ** 12 });
    expect(clamped.maxRequests).toBe(ADMIN_HARD_LIMITS.maxRequests);
    expect(clamped.maxDurationSeconds).toBe(ADMIN_HARD_LIMITS.maxDurationSeconds);
    expect(clamped.maxBytes).toBe(ADMIN_HARD_LIMITS.maxBytes);
  });

  it("§88: exceeding request/byte/time budgets throws BudgetExceededError", () => {
    const t = new ValidationBudgetTracker({ ...DEFAULT_VALIDATION_BUDGET, maxRequests: 2, maxBytes: 10 });
    t.consumeRequest(); t.consumeRequest();
    expect(() => t.consumeRequest()).toThrow(BudgetExceededError);
    expect(() => t.consumeBytes(11)).toThrow(BudgetExceededError);
    let clock = 1_000_000;
    const timed = new ValidationBudgetTracker({ ...DEFAULT_VALIDATION_BUDGET, maxDurationSeconds: 5 }, () => clock);
    clock += 6_000;
    expect(() => timed.checkDuration()).toThrow(/dead-man/);
  });

  it("rate limiter enforces per-dimension windows (§42)", () => {
    let clock = 0;
    const rl = new ValidationRateLimiter(() => clock);
    expect(rl.check("target", "t1", 2, 60).allowed).toBe(true);
    expect(rl.check("target", "t1", 2, 60).allowed).toBe(true);
    expect(rl.check("target", "t1", 2, 60).allowed).toBe(false);
    expect(rl.check("target", "t2", 2, 60).allowed).toBe(true); // different target unaffected
    clock = 61_000;
    expect(rl.check("target", "t1", 2, 60).allowed).toBe(true);
  });
});

describe("scope revalidation (§9/§85/§86)", () => {
  it("in-scope host resolving to a public IP passes", async () => {
    const r = await revalidateScope({ host: "app.fixture.example", scopeRules, resolver: async () => ["93.184.216.34"] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.resolvedIps).toEqual(["93.184.216.34"]);
  });

  it("§85: out-of-scope destination is BLOCKED", async () => {
    const r = await revalidateScope({ host: "other.example.org", scopeRules, resolver: async () => ["93.184.216.34"] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reasonCode).toBe("OUT_OF_SCOPE");
  });

  it("§86: DNS rebinding — host resolves to a protected IP at execution time → BLOCKED", async () => {
    const r = await revalidateScope({ host: "app.fixture.example", scopeRules, resolver: async () => ["169.254.169.254"] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reasonCode).toBe("PROTECTED_DESTINATION");
  });

  it("§86: resolution landing outside the approved CIDRs is BLOCKED", async () => {
    const cidrRules = { ...scopeRules, includeCidrs: ["203.0.113.0/24"] } as ScopeRules;
    const r = await revalidateScope({ host: "app.fixture.example", scopeRules: cidrRules, resolver: async () => ["198.51.100.10"] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reasonCode).toBe("OUT_OF_SCOPE");
  });
});

describe("kill switch matching (§43)", () => {
  const ctx = { organizationId: "org-1", workspaceId: "ws-1", targetId: "target-1", sessionId: "sess-1", scanId: "scan-1" };
  it("matches each level and prefers the most specific", () => {
    expect(activeKillSwitch([{ level: "GLOBAL", active: true }], ctx)?.level).toBe("GLOBAL");
    expect(activeKillSwitch([{ level: "WORKSPACE", workspaceId: "ws-2", active: true }], ctx)).toBeNull();
    expect(activeKillSwitch([{ level: "TARGET", scopeRef: "target-1", active: true }], ctx)?.level).toBe("TARGET");
    expect(activeKillSwitch([{ level: "SESSION", scopeRef: "sess-1", active: true }, { level: "GLOBAL", active: true }], ctx)?.level).toBe("SESSION");
    expect(activeKillSwitch([{ level: "GLOBAL", active: false }], ctx)).toBeNull();
  });
});

describe("callback tokens (§47/§48/§87)", () => {
  it("issue + verify: tenant binding, session binding, expiry, single use", () => {
    const now = new Date("2026-10-07T12:00:00.000Z");
    const issued = issueCallbackToken(600, now);
    const stored = { tokenHash: issued.tokenHash, workspaceId: "ws-1", sessionId: "sess-1", expiresAt: issued.expiresAt };
    expect(verifyCallbackToken({ presentedToken: issued.token, stored, workspaceId: "ws-1", sessionId: "sess-1", now }).ok).toBe(true);
    expect(verifyCallbackToken({ presentedToken: issued.token, stored, workspaceId: "ws-2", sessionId: "sess-1", now })).toMatchObject({ ok: false, reasonCode: "TENANT_MISMATCH" });
    expect(verifyCallbackToken({ presentedToken: issued.token, stored, workspaceId: "ws-1", sessionId: "sess-2", now })).toMatchObject({ ok: false, reasonCode: "SESSION_MISMATCH" });
    expect(verifyCallbackToken({ presentedToken: issued.token, stored, workspaceId: "ws-1", sessionId: "sess-1", now: new Date("2026-10-07T12:11:00.000Z") })).toMatchObject({ ok: false, reasonCode: "EXPIRED" });
    expect(verifyCallbackToken({ presentedToken: "wrong-token", stored, workspaceId: "ws-1", now })).toMatchObject({ ok: false, reasonCode: "TOKEN_MISMATCH" });
    expect(hashCallbackToken(issued.token)).toBe(issued.tokenHash);
  });
});

describe("evidence sanitization (§34/§91)", () => {
  it("redacts authorization headers, cookies, tokens, passwords, private keys, cloud credentials", () => {
    const dirty = buildValidationEvidence({
      type: "HTTP_RESPONSE",
      summary: "response carried Authorization: Bearer fixture-secret-token-12345 and password=hunter2",
      content: {
        headers: {
          authorization: "Bearer fixture-secret-token-12345",
          "set-cookie": "session=fixture-session-id-67890; HttpOnly",
          "x-api-key": "fixture-api-key-abcdef",
        },
        body: "the password is hunter2 and -----BEGIN RSA PRIVATE KEY-----\nMIIBog==\n-----END RSA PRIVATE KEY----- plus AKIAIOSFODNN7EXAMPLE",
        nested: { awsSecretAccessKey: "fixture-aws-secret", note: "token=abc123" },
      },
      sourceTool: "httpx",
    });
    const serialized = JSON.stringify(dirty);
    for (const secret of ["fixture-secret-token-12345", "fixture-session-id-67890", "fixture-api-key-abcdef", "hunter2", "MIIBog", "AKIAIOSFODNN7EXAMPLE", "fixture-aws-secret", "abc123"]) {
      expect(serialized).not.toContain(secret);
    }
    expect(dirty.checksum).toMatch(/^[a-f0-9]{64}$/);
    expect(sanitizeEvidenceText("Authorization: Bearer xyz")).toContain("[REDACTED]");
    expect(sanitizeEvidenceValue({ apiKey: "zzz" })).toEqual({ apiKey: "[REDACTED]" });
  });
});

describe("confidence updates (§36–§38)", () => {
  it("REPRODUCED meets the deterministic proof standard → VERIFIED + CONFIRMED", () => {
    const u = confidenceUpdateForOutcome("REPRODUCED", NOW);
    expect(u.validationConfidence).toBe("VERIFIED");
    expect(u.verificationStatus).toBe("CONFIRMED");
  });

  it("NOT_REPRODUCED is INCONCLUSIVE — never a false positive (§38)", () => {
    const u = confidenceUpdateForOutcome("NOT_REPRODUCED", NOW);
    expect(u.validationConfidence).toBe("INCONCLUSIVE");
    expect(u.verificationStatus).toBeUndefined();
    expect(u.note).toContain("NOT a false-positive");
  });

  it("manual analyst attestation verifies without any automated action (§32)", () => {
    const u = confidenceUpdateForManualValidation("VERIFIED", NOW);
    expect(u.validationConfidence).toBe("VERIFIED");
    expect(u.verificationStatus).toBe("CONFIRMED");
  });
});

describe("safe validators on lab fixtures (§83/§84)", () => {
  it("§84: header validation reproduces, captures evidence, updates confidence", async () => {
    const { result, evidence } = await runValidator("header-recheck", HEADER_FINDING);
    expect(result.outcome).toBe("REPRODUCED");
    expect(evidence.map((e) => e.type)).toEqual(["HTTP_REQUEST", "HTTP_RESPONSE"]);
    expect(confidenceUpdateForOutcome(result.outcome).validationConfidence).toBe("VERIFIED");
  });

  it("fixed header target validates as FIXED, not reproduced", async () => {
    const { result } = await runValidator("header-recheck", FIXED_HEADER_FINDING);
    expect(result.outcome).toBe("FIXED");
  });

  it("TLS, service, cloud, K8s, AD, source and container fixtures reproduce (§83)", async () => {
    expect((await runValidator("tls-recheck", TLS_FINDING)).result.outcome).toBe("REPRODUCED");
    expect((await runValidator("service-presence-recheck", SERVICE_FINDING)).result.outcome).toBe("REPRODUCED");
    expect((await runValidator("cloud-config-recheck", CLOUD_FINDING)).result.outcome).toBe("REPRODUCED");
    expect((await runValidator("kubernetes-posture-recheck", K8S_FINDING)).result.outcome).toBe("REPRODUCED");
    expect((await runValidator("ad-posture-recheck", AD_FINDING)).result.outcome).toBe("REPRODUCED");
    expect((await runValidator("source-recheck", SOURCE_FINDING)).result.outcome).toBe("REPRODUCED");
    expect((await runValidator("container-image-recheck", CONTAINER_FINDING)).result.outcome).toBe("REPRODUCED");
  });

  it("synthetic SQLi/XSS scanner fixtures reproduce via the governed recheck (§83)", async () => {
    const sqli = await runValidator("nuclei-recheck", SQLI_FINDING, { templateId: "sqli-fixture-template" });
    expect(sqli.result.outcome).toBe("REPRODUCED");
    expect(sqli.evidence[0]?.type).toBe("SCANNER_RESULT");
    const xss = await runValidator("nuclei-recheck", XSS_FINDING, { templateId: "xss-fixture-template" });
    expect(xss.result.outcome).toBe("REPRODUCED");
  });

  it("§91: evidence from the redaction-trap response contains no secrets", async () => {
    const { evidence } = await runValidator("nuclei-recheck", XSS_FINDING, { templateId: "xss-fixture-template" });
    expect(JSON.stringify(evidence)).not.toContain("fixture-secret-token-12345");
    const exposure = await runValidator("endpoint-exposure-recheck", { ...XSS_FINDING, vulnClass: "UNAUTHENTICATED_ENDPOINT" });
    const serialized = JSON.stringify(exposure.evidence);
    expect(serialized).not.toContain("fixture-secret-token-12345");
    expect(serialized).not.toContain("fixture-session-id-67890");
    expect(serialized).not.toContain("fixture-api-key-abcdef");
  });
});
