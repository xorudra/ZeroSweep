import { judgeRetest, type RetestPlan } from "@dsrclone/security-sdk";
import type { StageExecutor } from "./stage-executor";

/**
 * Targeted retest runner (Prompt 11 §55–§58). The store prepares a
 * single-stage child scan re-running the ORIGINAL tool/check; this
 * runner drives it through the ordinary StageExecutor so every gate
 * (authorization, verified target, approved assessment, scope, policy,
 * budget) is re-evaluated exactly as for the original scan (§57).
 *
 * Judgement (§58/§99): the stage must SUCCEED and produce evidence —
 * the original fingerprint among the produced findings means the issue
 * persists (REOPENED); a successful run without it means RESOLVED. A
 * denied/failed/unavailable stage is a FAILED retest, never a pass:
 * absence of evidence is not evidence of absence.
 */
export interface RetestStore {
  prepareRetestExecution(retestId: string): Promise<{ executionId: string; scanId: string; canonicalFingerprint: string } | null>;
  retestScanFingerprints(scanId: string): Promise<string[]>;
  completeRetest(retestId: string, outcome: "RESOLVED" | "REOPENED" | "FAILED", detail: string): Promise<void>;
}

export class RetestRunner {
  constructor(
    private readonly store: RetestStore,
    private readonly executor: Pick<StageExecutor, "run">,
  ) {}

  async runRetest(retestId: string): Promise<{ status: string; outcome?: string }> {
    const prepared = await this.store.prepareRetestExecution(retestId);
    if (!prepared) return { status: "NOT_PREPARED" };
    const outcome = await this.executor.run({
      kind: "STAGE_EXECUTION", scanId: prepared.scanId,
      stageId: "SAFE_VULNERABILITY_SCAN", toolExecutionId: prepared.executionId, attempt: 1,
    });
    if (outcome.status !== "COMPLETED" && outcome.status !== "ALREADY_COMPLETED") {
      const reason = outcome.status === "DENIED" ? ` (${outcome.reasonCode})` : "";
      await this.store.completeRetest(retestId, "FAILED", `targeted stage ended ${outcome.status}${reason} — the issue was NOT verified fixed`);
      return { status: "FAILED" };
    }
    const produced = await this.store.retestScanFingerprints(prepared.scanId);
    const plan: RetestPlan = {
      sourceTool: "retest",
      canonicalFingerprint: prepared.canonicalFingerprint,
      target: {},
      rationale: ["targeted retest judgement (§58)"],
    };
    const verdict = judgeRetest(plan, produced);
    await this.store.completeRetest(retestId, verdict, verdict === "RESOLVED"
      ? "targeted re-check completed; the original issue was not reproduced"
      : "targeted re-check reproduced the original issue");
    return { status: "COMPLETED", outcome: verdict };
  }
}
