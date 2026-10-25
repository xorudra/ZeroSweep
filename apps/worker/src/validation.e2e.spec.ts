import { describe, expect, it } from "vitest";
import {
  DEFAULT_ORGANIZATION_VALIDATION_POLICY,
  DEFAULT_VALIDATION_BUDGET,
  FIXTURE_SCOPE_RULES,
  FixtureValidationTransport,
  HEADER_FINDING,
  SQLI_FINDING,
  buildValidationPlan,
  type BudgetConsumption,
  type KillSwitchRecord,
  type SanitizedEvidence,
  type ValidationOutcome,
} from "@zerosweep/security-sdk";
import type { ScopeRules } from "@zerosweep/validation";
import {
  ValidationRunner,
  type PreparedValidation,
  type ValidationStore,
} from "./executors/validation-runner";

/**
 * Prompt 16 worker tests (§84–§95): the full re-check gauntlet runs in
 * the worker before any validator executes — approval validity and
 * plan-hash binding (§10/§93), scope revalidation with execution-time
 * DNS (§9/§86), budgets (§88), kill switches (§43/§89) and the
 * prohibited-automation wall (§95). All transports are fixtures; no
 * network is touched.
 */

interface SessionRecord {
  id: string;
  status: string;
  outcome?: ValidationOutcome;
  detail?: string;
  terminationReason?: string;
  evidence: SanitizedEvidence[];
  consumption?: BudgetConsumption;
}

class InMemoryValidationStore implements ValidationStore {
  sessions = new Map<string, SessionRecord>();
  findingState: { validationConfidence?: string; verificationStatus?: string; lastValidatedAt?: string } = {};
  killSwitches: KillSwitchRecord[] = [];
  resolvedIps: string[] = ["93.184.216.34"];
  private seq = 0;

  constructor(private readonly prepared: Omit<PreparedValidation, "sessionId">) {}

  async prepareValidationExecution(): Promise<PreparedValidation | null> {
    const sessionId = `session-${++this.seq}`;
    this.sessions.set(sessionId, { id: sessionId, status: "RUNNING", evidence: [] });
    return { ...this.prepared, sessionId };
  }

  async activeKillSwitches(): Promise<KillSwitchRecord[]> {
    return this.killSwitches;
  }

  async recordValidationEvidence(sessionId: string, evidence: SanitizedEvidence[]): Promise<void> {
    this.sessions.get(sessionId)?.evidence.push(...evidence);
  }

  async completeValidation(sessionId: string, outcome: ValidationOutcome, detail: string, consumption: BudgetConsumption): Promise<void> {
    const s = this.sessions.get(sessionId);
    if (!s) return;
    s.status = outcome === "REPRODUCED" || outcome === "FIXED" ? "SUCCEEDED" : "INCONCLUSIVE";
    s.outcome = outcome;
    s.detail = detail;
    s.consumption = consumption;
    if (outcome === "REPRODUCED") {
      this.findingState = { validationConfidence: "VERIFIED", verificationStatus: "CONFIRMED", lastValidatedAt: new Date().toISOString() };
    } else {
      this.findingState = { validationConfidence: "INCONCLUSIVE", lastValidatedAt: new Date().toISOString() };
    }
  }

  async blockValidation(sessionId: string, reasonCode: string, message: string): Promise<void> {
    const s = this.sessions.get(sessionId);
    if (!s) return;
    s.status = "BLOCKED";
    s.terminationReason = `${reasonCode}: ${message}`;
  }

  async cancelValidation(sessionId: string, reason: string): Promise<void> {
    const s = this.sessions.get(sessionId);
    if (!s) return;
    s.status = "CANCELLED";
    s.terminationReason = reason;
  }

  async failValidation(sessionId: string, terminationReason: string, message: string): Promise<void> {
    const s = this.sessions.get(sessionId);
    if (!s) return;
    s.status = "FAILED";
    s.terminationReason = `${terminationReason}: ${message}`;
  }

  async resolveHost(): Promise<string[]> {
    return this.resolvedIps;
  }
}

function preparedBase(overrides: Partial<Omit<PreparedValidation, "sessionId">> = {}): Omit<PreparedValidation, "sessionId"> {
  const { plan, planHash } = buildValidationPlan({
    validatorSlug: "header-recheck",
    finding: HEADER_FINDING,
    targetId: "target-1",
    budget: DEFAULT_VALIDATION_BUDGET,
  });
  return {
    requestId: "req-1",
    workspaceId: "ws-1",
    organizationId: "org-1",
    findingId: HEADER_FINDING.id,
    finding: HEADER_FINDING,
    targetId: "target-1",
    validatorSlug: "header-recheck",
    riskClass: "SAFE",
    plan,
    planHash,
    parameters: {},
    requestedBy: "user-requester",
    environment: "PRODUCTION",
    policy: { ...DEFAULT_ORGANIZATION_VALIDATION_POLICY },
    authorization: { targetVerified: true, assessmentApproved: true },
    scopeRules: FIXTURE_SCOPE_RULES as ScopeRules,
    approval: null,
    ...overrides,
  };
}

describe("ValidationRunner (§12/§13)", () => {
  it("§84: SAFE header validation runs end-to-end — evidence sanitized, finding VERIFIED", async () => {
    const store = new InMemoryValidationStore(preparedBase());
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result).toMatchObject({ status: "COMPLETED", outcome: "REPRODUCED" });
    const session = [...store.sessions.values()][0]!;
    expect(session.status).toBe("SUCCEEDED");
    expect(session.evidence.map((e) => e.type)).toEqual(["HTTP_REQUEST", "HTTP_RESPONSE"]);
    expect(session.evidence.every((e) => /^[a-f0-9]{64}$/.test(e.checksum))).toBe(true);
    expect(store.findingState.validationConfidence).toBe("VERIFIED");
    expect(store.findingState.verificationStatus).toBe("CONFIRMED");
  });

  it("§84/§91: evidence from a secret-carrying response is stored sanitized", async () => {
    const { plan, planHash } = buildValidationPlan({
      validatorSlug: "endpoint-exposure-recheck",
      finding: { ...SQLI_FINDING, vulnClass: "UNAUTHENTICATED_ENDPOINT", endpoint: "https://app.fixture.example/reflect?input=fixture" },
      targetId: "target-1",
      budget: DEFAULT_VALIDATION_BUDGET,
    });
    const store = new InMemoryValidationStore(preparedBase({
      validatorSlug: "endpoint-exposure-recheck",
      plan, planHash,
      finding: { ...SQLI_FINDING, vulnClass: "UNAUTHENTICATED_ENDPOINT", endpoint: "https://app.fixture.example/reflect?input=fixture" },
      findingId: SQLI_FINDING.id,
    }));
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result.status).toBe("COMPLETED");
    const serialized = JSON.stringify([...store.sessions.values()][0]?.evidence ?? []);
    expect(serialized).not.toContain("fixture-secret-token-12345");
    expect(serialized).not.toContain("fixture-session-id-67890");
    expect(serialized).not.toContain("fixture-api-key-abcdef");
  });

  it("not reproduced → INCONCLUSIVE, finding is NOT marked verified or false-positive (§38)", async () => {
    const { plan, planHash } = buildValidationPlan({
      validatorSlug: "nuclei-recheck",
      finding: SQLI_FINDING,
      targetId: "target-1",
      parameters: { templateId: "unknown-template" },
      budget: DEFAULT_VALIDATION_BUDGET,
    });
    const store = new InMemoryValidationStore(preparedBase({
      validatorSlug: "nuclei-recheck", plan, planHash,
      finding: SQLI_FINDING, findingId: SQLI_FINDING.id, parameters: { templateId: "unknown-template" },
    }));
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result).toMatchObject({ status: "COMPLETED", outcome: "NOT_REPRODUCED" });
    expect(store.findingState.validationConfidence).toBe("INCONCLUSIVE");
    expect(store.findingState.verificationStatus).toBeUndefined();
  });

  it("§93: an approval that expired before execution BLOCKS the run", async () => {
    const { plan, planHash } = buildValidationPlan({
      validatorSlug: "nuclei-recheck", finding: SQLI_FINDING, targetId: "target-1",
      parameters: { templateId: "sqli-fixture-template" }, budget: DEFAULT_VALIDATION_BUDGET,
    });
    const store = new InMemoryValidationStore(preparedBase({
      validatorSlug: "nuclei-recheck", riskClass: "REVIEW_REQUIRED", plan, planHash,
      finding: SQLI_FINDING, findingId: SQLI_FINDING.id, parameters: { templateId: "sqli-fixture-template" },
      approval: {
        approverId: "user-approver", decision: "APPROVED", planHash,
        targetId: "target-1", findingId: SQLI_FINDING.id, validatorSlug: "nuclei-recheck",
        expiresAt: "2000-01-01T00:00:00.000Z",
      },
    }));
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result).toMatchObject({ status: "BLOCKED", reasonCode: "APPROVAL_EXPIRED" });
    expect([...store.sessions.values()][0]?.status).toBe("BLOCKED");
  });

  it("§10: a plan edited after approval BLOCKS execution (hash mismatch)", async () => {
    const { plan, planHash } = buildValidationPlan({
      validatorSlug: "nuclei-recheck", finding: SQLI_FINDING, targetId: "target-1",
      parameters: { templateId: "sqli-fixture-template" }, budget: DEFAULT_VALIDATION_BUDGET,
    });
    const store = new InMemoryValidationStore(preparedBase({
      validatorSlug: "nuclei-recheck", riskClass: "REVIEW_REQUIRED", plan, planHash,
      finding: SQLI_FINDING, findingId: SQLI_FINDING.id, parameters: { templateId: "sqli-fixture-template" },
      approval: {
        approverId: "user-approver", decision: "APPROVED", planHash: "a-different-plan-hash",
        targetId: "target-1", findingId: SQLI_FINDING.id, validatorSlug: "nuclei-recheck",
        expiresAt: "2999-01-01T00:00:00.000Z",
      },
    }));
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result).toMatchObject({ status: "BLOCKED", reasonCode: "APPROVAL_PLAN_MISMATCH" });
  });

  it("§86: DNS rebinding at execution time BLOCKS the run", async () => {
    const store = new InMemoryValidationStore(preparedBase());
    store.resolvedIps = ["169.254.169.254"];
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result).toMatchObject({ status: "BLOCKED", reasonCode: "PROTECTED_DESTINATION" });
  });

  it("§85: destination outside scope BLOCKS the run", async () => {
    const store = new InMemoryValidationStore(preparedBase({
      scopeRules: { ...FIXTURE_SCOPE_RULES, includeHosts: ["other.fixture.example"] } as ScopeRules,
    }));
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result.status).toBe("BLOCKED");
  });

  it("§88: budget exhaustion terminates the session safely — FAILED, never a pass", async () => {
    const { plan, planHash } = buildValidationPlan({
      validatorSlug: "header-recheck", finding: HEADER_FINDING, targetId: "target-1",
      budget: { ...DEFAULT_VALIDATION_BUDGET, maxBytes: 8 },
    });
    const store = new InMemoryValidationStore(preparedBase({ plan, planHash }));
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result).toMatchObject({ status: "FAILED", reasonCode: "BUDGET_EXCEEDED" });
    const session = [...store.sessions.values()][0]!;
    expect(session.status).toBe("FAILED");
    expect(session.terminationReason).toContain("BUDGET_EXCEEDED");
    expect(store.findingState.validationConfidence).toBeUndefined();
  });

  it("§43: kill switch active before start cancels without executing", async () => {
    const store = new InMemoryValidationStore(preparedBase());
    store.killSwitches = [{ level: "WORKSPACE", workspaceId: "ws-1", active: true }];
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result).toMatchObject({ status: "CANCELLED", reasonCode: "KILL_SWITCH_ACTIVE" });
    expect([...store.sessions.values()][0]?.evidence.length).toBe(0);
  });

  it("§89: kill switch activated mid-flight terminates the running validation", async () => {
    const store = new InMemoryValidationStore(preparedBase());
    const runner = new ValidationRunner(store, new FixtureValidationTransport(400), { killSwitchPollMs: 10 });
    const running = runner.runValidation("req-1");
    setTimeout(() => { store.killSwitches = [{ level: "GLOBAL", active: true }]; }, 60);
    const result = await running;
    expect(result).toMatchObject({ status: "CANCELLED", reasonCode: "KILL_SWITCH_ACTIVE" });
    const session = [...store.sessions.values()][0]!;
    expect(session.status).toBe("CANCELLED");
    expect(session.terminationReason).toContain("kill switch");
    expect(store.findingState.validationConfidence).toBeUndefined();
  });

  it("§95: a prohibited technique can never reach a validator — BLOCKED by policy in the worker", async () => {
    const store = new InMemoryValidationStore(preparedBase({
      validatorSlug: "password-spraying",
      riskClass: "PROHIBITED_AUTOMATION",
    }));
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    const result = await runner.runValidation("req-1");
    expect(result).toMatchObject({ status: "BLOCKED", reasonCode: "PROHIBITED_AUTOMATION" });
  });

  it("an unprepared request is reported, not silently dropped", async () => {
    const store = new InMemoryValidationStore(preparedBase());
    store.prepareValidationExecution = async () => null;
    const runner = new ValidationRunner(store, new FixtureValidationTransport(), { killSwitchPollMs: 10 });
    expect(await runner.runValidation("missing")).toEqual({ status: "NOT_PREPARED" });
  });
});
