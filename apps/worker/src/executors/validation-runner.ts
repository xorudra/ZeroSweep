import {
  BudgetExceededError,
  ValidationBudgetTracker,
  activeKillSwitch,
  budgetedTransport,
  buildValidationEvidence,
  confidenceUpdateForOutcome,
  evaluateValidationPolicy,
  getValidatorImplementation,
  revalidateScope,
  type BudgetConsumption,
  type KillSwitchContext,
  type KillSwitchRecord,
  type OrganizationValidationPolicy,
  type SanitizedEvidence,
  type ScopeRules,
  type ValidationApprovalView,
  type ValidationFindingView,
  type ValidationOutcome,
  type ValidationPlan,
  type ValidationRiskClass,
  type ValidationTransport,
} from "@dsrclone/security-sdk";

/**
 * Controlled validation runner (Prompt 16 §12/§13/§43–§46). Runs on
 * isolated validation workers — never inside the API (§45). Before a
 * validator executes, the runner re-checks EVERYTHING against trusted
 * store state (the Prompt 4/11 pattern): the request must still be
 * executable, the approval (when required) must be present, unexpired
 * and bound to the stored plan hash (§10), the authorization snapshot
 * must still be valid (§8), the destination is re-resolved and
 * re-validated against scope (§9/§86), and no kill switch may be
 * active at any level (§43).
 *
 * During execution the transport is wrapped twice: a budget layer
 * (§40/§44/§88) and a kill-switch layer that re-reads switch state on
 * every call; a watcher also races the run so a switch flipped
 * mid-flight terminates the session (§89). A blocked/failed/cancelled
 * validation NEVER raises finding confidence.
 */

export class ValidationCancelledError extends Error {
  constructor(message = "validation cancelled by kill switch") {
    super(message);
    this.name = "ValidationCancelledError";
  }
}

/** Honest production default (§45/§46): until a deployment provisions
 *  governed egress transports on its validation workers, every
 *  transport method refuses — sessions fail truthfully instead of
 *  fabricating reproductions from fixture data. Tests inject the
 *  fixture transport explicitly. */
export class UnconfiguredValidationTransport implements ValidationTransport {
  private refuse(): never {
    throw new Error("VALIDATION_TRANSPORT_NOT_PROVISIONED: this worker has no governed validation transport configured");
  }
  async httpGet(): Promise<never> { return this.refuse(); }
  async tlsInspect(): Promise<never> { return this.refuse(); }
  async serviceProbe(): Promise<never> { return this.refuse(); }
  async configurationCheck(): Promise<never> { return this.refuse(); }
  async scannerRecheck(): Promise<never> { return this.refuse(); }
}

export interface PreparedValidation {
  requestId: string;
  sessionId: string;
  workspaceId: string;
  organizationId?: string;
  findingId: string;
  finding: ValidationFindingView;
  targetId: string;
  scanId?: string;
  validatorSlug: string;
  riskClass: ValidationRiskClass;
  plan: ValidationPlan;
  planHash: string;
  parameters: Record<string, string | number | boolean>;
  requestedBy: string;
  environment: "PRODUCTION" | "LAB";
  policy: OrganizationValidationPolicy;
  assetCriticality?: string | null;
  authorization: { targetVerified: boolean; assessmentApproved: boolean; expiresAt?: string };
  scopeRules: ScopeRules;
  approval?: ValidationApprovalView | null;
}

export interface ValidationStore {
  /** Creates the session (RUNNING) and returns everything the runner
   *  must re-check. Null = request not executable (wrong status,
   *  expired, missing) — reported, never silently dropped. */
  prepareValidationExecution(requestId: string, workerId: string): Promise<PreparedValidation | null>;
  activeKillSwitches(ctx: KillSwitchContext): Promise<KillSwitchRecord[]>;
  recordValidationEvidence(sessionId: string, evidence: SanitizedEvidence[]): Promise<void>;
  /** Persists the outcome: session + request status, finding
   *  validation-confidence update (§36/§37), history + audit. */
  completeValidation(sessionId: string, outcome: ValidationOutcome, detail: string, consumption: BudgetConsumption): Promise<void>;
  blockValidation(sessionId: string, reasonCode: string, message: string): Promise<void>;
  cancelValidation(sessionId: string, reason: string): Promise<void>;
  failValidation(sessionId: string, terminationReason: string, message: string): Promise<void>;
  /** DNS resolution AT EXECUTION TIME (§9) — the rebinding defense
   *  depends on resolving here, never at request time. */
  resolveHost(host: string): Promise<string[]>;
}

export interface ValidationRunnerOptions {
  workerId?: string;
  killSwitchPollMs?: number;
  now?: () => number;
}

export class ValidationRunner {
  constructor(
    private readonly store: ValidationStore,
    private readonly transport: ValidationTransport,
    private readonly options: ValidationRunnerOptions = {},
  ) {}

  async runValidation(requestId: string): Promise<{ status: string; outcome?: string; reasonCode?: string }> {
    const prepared = await this.store.prepareValidationExecution(requestId, this.options.workerId ?? "validation-worker");
    if (!prepared) return { status: "NOT_PREPARED" };
    const { sessionId } = prepared;
    const killCtx: KillSwitchContext = {
      ...(prepared.organizationId ? { organizationId: prepared.organizationId } : {}),
      workspaceId: prepared.workspaceId,
      ...(prepared.scanId ? { scanId: prepared.scanId } : {}),
      targetId: prepared.targetId,
      sessionId,
    };

    // §43: a kill switch active before start blocks the run outright.
    const preSwitch = activeKillSwitch(await this.store.activeKillSwitches(killCtx), killCtx);
    if (preSwitch) {
      await this.store.cancelValidation(sessionId, `kill switch active at level ${preSwitch.level} before execution (§43)`);
      return { status: "CANCELLED", reasonCode: "KILL_SWITCH_ACTIVE" };
    }

    // §7/§8/§10: policy re-evaluation with trusted state. An approval
    // that was valid at request time may have expired, and the plan
    // hash on file must still match what was approved.
    const decision = evaluateValidationPolicy({
      policy: prepared.policy,
      environment: prepared.environment,
      authorization: prepared.authorization,
      scope: { inScope: true }, // host-level scope is revalidated below (§9)
      assetCriticality: prepared.assetCriticality ?? null,
      technique: prepared.validatorSlug,
      riskClass: prepared.riskClass,
      requestedBy: prepared.requestedBy,
      planHash: prepared.planHash,
      targetId: prepared.targetId,
      findingId: prepared.findingId,
      approval: prepared.approval ?? null,
      now: new Date(),
    });
    if (decision.decision !== "ALLOW") {
      await this.store.blockValidation(sessionId, decision.reasonCode, decision.message);
      return { status: "BLOCKED", reasonCode: decision.reasonCode };
    }

    // §9/§86: scope revalidation against live resolution. Any resolved
    // address that is protected or out of scope blocks execution.
    const scopeCheck = await revalidateScope({
      ...(prepared.plan.targetRef.host ? { host: prepared.plan.targetRef.host } : {}),
      ...(prepared.plan.targetRef.port ? { port: prepared.plan.targetRef.port } : {}),
      ...(prepared.plan.targetRef.endpoint ? { url: prepared.plan.targetRef.endpoint } : {}),
      scopeRules: prepared.scopeRules,
      resolver: (host) => this.store.resolveHost(host),
    });
    if (!scopeCheck.ok) {
      await this.store.blockValidation(sessionId, scopeCheck.reasonCode, scopeCheck.message);
      return { status: "BLOCKED", reasonCode: scopeCheck.reasonCode };
    }

    const validator = getValidatorImplementation(prepared.validatorSlug);
    if (!validator) {
      await this.store.blockValidation(sessionId, "TECHNIQUE_NOT_IN_CATALOG", `validator ${prepared.validatorSlug} has no governed implementation`);
      return { status: "BLOCKED", reasonCode: "TECHNIQUE_NOT_IN_CATALOG" };
    }

    // §40/§44/§88: budget tracker + dead-man timeout on every call.
    const budget = new ValidationBudgetTracker(prepared.plan.budget, this.options.now);
    let cancelled = false;
    const killGuarded: ValidationTransport = {
      httpGet: async (url) => { await this.assertNotKilled(killCtx, () => cancelled); return this.transport.httpGet(url); },
      tlsInspect: async (h, p) => { await this.assertNotKilled(killCtx, () => cancelled); return this.transport.tlsInspect(h, p); },
      serviceProbe: async (h, p) => { await this.assertNotKilled(killCtx, () => cancelled); return this.transport.serviceProbe(h, p); },
      configurationCheck: async (k, r) => { await this.assertNotKilled(killCtx, () => cancelled); return this.transport.configurationCheck(k, r); },
      scannerRecheck: async (t, r) => { await this.assertNotKilled(killCtx, () => cancelled); return this.transport.scannerRecheck(t, r); },
    };
    const transport = budgetedTransport(killGuarded, budget);
    const ctx = { finding: prepared.finding, parameters: prepared.parameters, transport, budget };

    // §43/§89: watcher — if a kill switch activates mid-flight, the
    // session is cancelled even if the validator is inside a long call.
    const pollMs = this.options.killSwitchPollMs ?? 250;
    let watcherTimer: ReturnType<typeof setInterval> | undefined;
    const watcher = new Promise<never>((_resolve, reject) => {
      watcherTimer = setInterval(() => {
        void this.store.activeKillSwitches(killCtx)
          .then((switches) => {
            if (activeKillSwitch(switches, killCtx)) {
              cancelled = true;
              reject(new ValidationCancelledError());
            }
          })
          .catch(() => { /* a store hiccup must not kill a healthy run */ });
      }, pollMs);
    });

    try {
      await validator.prepare(ctx);
      const result = await Promise.race([validator.execute(ctx), watcher]);
      clearInterval(watcherTimer);
      await validator.cleanup(ctx);
      budget.checkDuration();

      // §33–§35: evidence is sanitized + checksummed before storage.
      const evidence = validator.parseEvidence(result).map((draft) => buildValidationEvidence(draft));
      await this.store.recordValidationEvidence(sessionId, evidence);
      await this.store.completeValidation(sessionId, result.outcome, result.detail, budget.consumption());
      return { status: "COMPLETED", outcome: result.outcome };
    } catch (err) {
      clearInterval(watcherTimer);
      await validator.cleanup(ctx).catch(() => undefined);
      if (err instanceof ValidationCancelledError || cancelled) {
        await this.store.cancelValidation(sessionId, "kill switch activated during execution — validation process terminated (§43/§89)");
        return { status: "CANCELLED", reasonCode: "KILL_SWITCH_ACTIVE" };
      }
      if (err instanceof BudgetExceededError) {
        await this.store.failValidation(sessionId, `BUDGET_EXCEEDED:${err.dimension}`, `${err.message} — session terminated safely (§88)`);
        return { status: "FAILED", reasonCode: "BUDGET_EXCEEDED" };
      }
      const message = err instanceof Error ? err.message : "unknown validation error";
      await this.store.failValidation(sessionId, "VALIDATOR_ERROR", message);
      return { status: "FAILED", reasonCode: "VALIDATOR_ERROR" };
    }
  }

  private async assertNotKilled(ctx: KillSwitchContext, isCancelled: () => boolean): Promise<void> {
    if (isCancelled()) throw new ValidationCancelledError();
    const switches = await this.store.activeKillSwitches(ctx);
    if (activeKillSwitch(switches, ctx)) throw new ValidationCancelledError();
  }
}

/** Confidence write-back helper shared by store implementations:
 *  maps an outcome to the finding update (§36–§38). Exported so the
 *  Prisma and fake stores cannot drift apart. */
export function findingUpdateForOutcome(outcome: ValidationOutcome) {
  return confidenceUpdateForOutcome(outcome);
}
