import { judgeRetest, type RetestPlan } from "@zerosweep/security-sdk";
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
  prepareRetestExecution(retestId: string): Promise<{ executionId: string; scanId: string; canonicalFingerprint: string; stageId?: string; cloudAnalysisSection?: string; directoryAnalysisSection?: string } | null>;
  retestScanFingerprints(scanId: string): Promise<string[]>;
  completeRetest(retestId: string, outcome: "RESOLVED" | "REOPENED" | "FAILED", detail: string): Promise<void>;
  /** Prompt 14 §73: after a cloud retest's inventory stage succeeds,
   *  the store runs the ONE targeted analysis section so the child
   *  scan holds the section evidence the judgement compares. */
  analyzeCloudSection?(scanId: string, section: string): Promise<{ findings: number; assessments: number } | null>;
  /** Prompt 15 §84: after a directory retest's collection stage
   *  succeeds, the store re-evaluates the dedicated LDAP posture
   *  section over the fresh inventory before judgement. */
  analyzeDirectoryLdapPosture?(scanId: string): Promise<{ findings: number; assessments: number } | null>;
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
      // Prompt 13 §77: cloud-native findings retest in their ORIGINAL
      // stage (image rescan / manifest rescan / posture reassessment /
      // benchmark rerun); all other findings keep the Prompt 11 stage.
      stageId: prepared.stageId ?? "SAFE_VULNERABILITY_SCAN", toolExecutionId: prepared.executionId, attempt: 1,
    });
    if (outcome.status !== "COMPLETED" && outcome.status !== "ALREADY_COMPLETED") {
      const reason = outcome.status === "DENIED" ? ` (${outcome.reasonCode})` : "";
      await this.store.completeRetest(retestId, "FAILED", `targeted stage ended ${outcome.status}${reason} — the issue was NOT verified fixed`);
      return { status: "FAILED" };
    }
    // Prompt 14 §73: cloud retests judge on ANALYSIS evidence — run
    // the targeted section over the child scan's fresh inventory
    // before comparing fingerprints. If the section cannot run, the
    // retest is inconclusive → FAILED, never a silent pass.
    if (prepared.cloudAnalysisSection) {
      if (!this.store.analyzeCloudSection) {
        await this.store.completeRetest(retestId, "FAILED", "cloud analysis hook unavailable — the issue was NOT verified fixed");
        return { status: "FAILED" };
      }
      const section = await this.store.analyzeCloudSection(prepared.scanId, prepared.cloudAnalysisSection).catch(() => null);
      if (!section) {
        await this.store.completeRetest(retestId, "FAILED", "cloud analysis section produced no evidence — the issue was NOT verified fixed");
        return { status: "FAILED" };
      }
    }
    // Prompt 15 §84: directory retests judge on fresh SECTION evidence
    // too — re-evaluate the LDAP posture section over the child scan's
    // fresh collection. A section that cannot run is inconclusive →
    // FAILED, never a silent pass.
    if (prepared.directoryAnalysisSection) {
      if (!this.store.analyzeDirectoryLdapPosture) {
        await this.store.completeRetest(retestId, "FAILED", "directory analysis hook unavailable — the issue was NOT verified fixed");
        return { status: "FAILED" };
      }
      const section = await this.store.analyzeDirectoryLdapPosture(prepared.scanId).catch(() => null);
      if (!section) {
        await this.store.completeRetest(retestId, "FAILED", "directory analysis section produced no evidence — the issue was NOT verified fixed");
        return { status: "FAILED" };
      }
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
