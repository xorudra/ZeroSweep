import { Inject, Injectable } from "@nestjs/common";
import { createHash } from "node:crypto";
import {
  checkPayloadSize,
  parseBitbucketEvent, parseGitHubEvent, parseGitLabEvent,
  sanitizeUntrustedText,
  verifyBitbucketSignature, verifyGitHubSignature, verifyGitLabToken,
  type NormalizedSourceEvent,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { IntegrationSecretResolver } from "../core/transport";
import { ScanTriggerService } from "../cicd/scan-trigger.service";
import { QualityGatesService } from "../quality-gates/quality-gates.service";
import { RepositoriesIntegrationService } from "../repositories/repositories-integration.service";

type Row = Record<string, unknown>;

export interface WebhookReceipt {
  status: "PROCESSED" | "IGNORED_DUPLICATE" | "IGNORED" | "BLOCKED" | "REJECTED";
  reasonCode?: string;
  detail: string;
  assessmentId?: string;
  scanId?: string;
  httpStatus: number;
}

const PROVIDER_EVENT_HEADERS: Record<string, { event: string; delivery: string }> = {
  GITHUB: { event: "x-github-event", delivery: "x-github-delivery" },
  GITLAB: { event: "x-gitlab-event", delivery: "x-gitlab-event-uuid" },
  BITBUCKET: { event: "x-event-key", delivery: "x-request-uuid" },
};

/**
 * Inbound provider webhooks (Prompt 24 §15–§17, §25, §81–§84,
 * §108, §111–§116). Webhooks are HOSTILE input:
 *
 * 1. Payload size is capped before parsing (§82).
 * 2. The signature/token is verified BEFORE any payload field is
 *    trusted, against the secret REFERENCE of a configured
 *    integration of that provider (§15/§25). An unverifiable delivery
 *    is rejected and recorded — never processed.
 * 3. Delivery IDs are idempotency keys: a replay is recorded once and
 *    ignored thereafter (§16).
 * 4. A verified webhook may only TRIGGER governed work for a
 *    repository that is already linked (the allowlist, §86/§116) and
 *    whose policy enables it — through ScanTriggerService, which
 *    re-checks VERIFIED + APPROVED at fire time. It can never
 *    approve, verify, or create scope.
 * 5. The payload itself is never stored — only a sanitized summary
 *    (§81/§83).
 */
@Injectable()
export class WebhooksService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly secrets: IntegrationSecretResolver,
    private readonly triggers: ScanTriggerService,
    private readonly gates: QualityGatesService,
    private readonly repositories: RepositoriesIntegrationService,
  ) {}

  async receive(
    provider: "GITHUB" | "GITLAB" | "BITBUCKET",
    headers: Record<string, string | undefined>,
    rawBody: string,
    integrationId?: string,
  ): Promise<WebhookReceipt> {
    const headerNames = PROVIDER_EVENT_HEADERS[provider]!;
    const eventType = headers[headerNames.event] ?? "unknown";
    const deliveryId = headers[headerNames.delivery] ?? this.fallbackDeliveryId(provider, rawBody);

    const sizeProblem = checkPayloadSize(rawBody);
    if (sizeProblem) {
      await this.record(null, null, provider, deliveryId, eventType, "MISSING", "REJECTED", sizeProblem.reasonCode ?? "PAYLOAD_TOO_LARGE");
      return { status: "REJECTED", reasonCode: sizeProblem.reasonCode, detail: sizeProblem.detail, httpStatus: 413 };
    }

    // Attribution is bound to ONE tenant before/regardless of secret
    // trial (audit: inbound-global-secret-match). When the route
    // names an integration, the candidate set is exactly that row.
    // Otherwise every verifying candidate is collected: a delivery
    // that verifies against MORE THAN ONE integration (e.g. two
    // tenants sharing one env: secret) is ambiguous and rejected —
    // never attributed to whichever row the database returned first.
    // Verification precedes all payload trust (§15).
    const candidates = integrationId
      ? await this.prisma.integration.findMany({
          where: { id: integrationId, type: provider, enabled: true },
        }) as Row[]
      : await this.prisma.integration.findMany({
          where: { type: provider, enabled: true },
        }) as Row[];
    const verifiedCandidates: Row[] = [];
    let sawResolvableSecret = false;
    for (const candidate of candidates) {
      const config = (candidate.configuration ?? candidate.config ?? {}) as Row;
      const reference = (config.webhookSecretReference as string) ?? (candidate.secretReference as string);
      const secret = this.secrets.resolve(reference);
      if (!secret) continue;
      sawResolvableSecret = true;
      const verdict = provider === "GITHUB"
        ? verifyGitHubSignature({ rawBody, signatureHeader: headers["x-hub-signature-256"], secret })
        : provider === "GITLAB"
          ? verifyGitLabToken({ tokenHeader: headers["x-gitlab-token"], secret })
          : verifyBitbucketSignature({ rawBody, signatureHeader: headers["x-hub-signature"], secret });
      if (verdict.ok) verifiedCandidates.push(candidate);
    }
    if (verifiedCandidates.length > 1) {
      await this.record(null, null, provider, deliveryId, eventType, "INVALID", "REJECTED", "AMBIGUOUS_INTEGRATION");
      return {
        status: "REJECTED", reasonCode: "AMBIGUOUS_INTEGRATION",
        detail: "webhook signature verifies against multiple integrations — delivery rejected instead of being attributed to the first match",
        httpStatus: 401,
      };
    }
    const verified: Row | null = verifiedCandidates[0] ?? null;
    if (!verified) {
      await this.record(null, null, provider, deliveryId, eventType, candidates.length === 0 ? "MISSING" : "INVALID", "REJECTED",
        candidates.length === 0 ? "NO_INTEGRATION_CONFIGURED" : sawResolvableSecret ? "SIGNATURE_INVALID" : "WEBHOOK_SECRET_UNRESOLVED");
      if (candidates.length > 0) {
        await this.audit.record({
          action: "INTEGRATION_AUTH_FAILED", resourceType: "Integration", resourceId: candidates[0]!.id as string,
          metadata: { provider, eventType, deliveryId },
        }).catch(() => undefined);
      }
      return {
        status: "REJECTED",
        reasonCode: candidates.length === 0 ? "NO_INTEGRATION_CONFIGURED" : "SIGNATURE_INVALID",
        detail: "webhook signature/token verification failed — delivery rejected before any payload processing (§15)",
        httpStatus: 401,
      };
    }

    const workspaceId = verified.workspaceId as string;
    const verifiedIntegrationId = verified.id as string;

    // §16: replay protection — the same delivery id is processed once.
    const prior = await this.prisma.inboundIntegrationEvent.findFirst({
      where: { integrationId: verifiedIntegrationId, deliveryId },
    });
    if (prior) {
      return { status: "IGNORED_DUPLICATE", detail: "duplicate delivery id — idempotently ignored (§16)", httpStatus: 200 };
    }
    const recordRow = await this.record(workspaceId, verifiedIntegrationId, provider, deliveryId, eventType, "VALID", "RECEIVED", null);

    let payload: unknown;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      await this.finishRecord(recordRow, "REJECTED", "PAYLOAD_NOT_JSON");
      return { status: "REJECTED", reasonCode: "PAYLOAD_NOT_JSON", detail: "webhook payload is not JSON", httpStatus: 400 };
    }

    await this.audit.record({
      actorId: verified.createdBy as string, organizationId: verified.organizationId as string, workspaceId,
      action: "SOURCE_WEBHOOK_RECEIVED", resourceType: "Integration", resourceId: verifiedIntegrationId,
      metadata: { provider, eventType, deliveryId },
    }).catch(() => undefined);

    const event: NormalizedSourceEvent | null = provider === "GITHUB"
      ? parseGitHubEvent(eventType, payload)
      : provider === "GITLAB"
        ? parseGitLabEvent(eventType, payload)
        : parseBitbucketEvent(eventType, payload);
    if (!event || !event.externalRepoId) {
      await this.finishRecord(recordRow, "IGNORED", "UNSUPPORTED_OR_MALFORMED_EVENT");
      return { status: "IGNORED", detail: "event type not actionable or payload malformed — recorded and ignored", httpStatus: 200 };
    }

    const link = await this.repositories.linkForExternal(workspaceId, verifiedIntegrationId, event.externalRepoId);
    if (!link) {
      // §86/§116: the repository allowlist is the link table. An
      // unlinked repository can never trigger work.
      await this.finishRecord(recordRow, "IGNORED", "REPOSITORY_NOT_LINKED");
      return { status: "IGNORED", reasonCode: "REPOSITORY_NOT_LINKED", detail: "repository is not linked in this workspace — no scan triggered (§116)", httpStatus: 200 };
    }
    const repository = await this.prisma.sourceRepository.findFirst({
      where: { id: link.sourceRepositoryId as string, workspaceId },
    }) as Row | null;
    if (!repository) {
      await this.finishRecord(recordRow, "IGNORED", "REPOSITORY_MISSING");
      return { status: "IGNORED", detail: "linked repository row missing", httpStatus: 200 };
    }
    const policy = await this.prisma.repositorySecurityPolicy.findFirst({
      where: { workspaceId, sourceRepositoryId: repository.id as string },
    }) as Row | null;

    if (event.kind === "PUSH") {
      const isDefault = !link.defaultBranch || !event.branch || event.branch === link.defaultBranch;
      const allowed = policy && (policy.scanOnPush === true || (isDefault && policy.scanDefaultBranch === true));
      if (!allowed) {
        await this.finishRecord(recordRow, "IGNORED", "POLICY_SCAN_ON_PUSH_DISABLED");
        return { status: "IGNORED", detail: "repository policy does not enable push-triggered scans (§31)", httpStatus: 200 };
      }
      const outcome = await this.triggers.triggerRepositoryScan({
        workspaceId, repository, actorUserId: link.createdBy as string, purpose: `${provider.toLowerCase()}.push`,
      });
      await this.finishRecord(recordRow, outcome.started ? "PROCESSED" : "BLOCKED", outcome.reasonCode ?? null);
      return {
        status: outcome.started ? "PROCESSED" : "BLOCKED",
        reasonCode: outcome.reasonCode, detail: outcome.detail, scanId: outcome.scanId, httpStatus: 200,
      };
    }

    if (event.kind === "PULL_REQUEST" && event.pullRequest) {
      if (!policy || policy.scanOnPullRequest !== true) {
        await this.finishRecord(recordRow, "IGNORED", "POLICY_SCAN_ON_PR_DISABLED");
        return { status: "IGNORED", detail: "repository policy does not enable PR-triggered scans (§31)", httpStatus: 200 };
      }
      const pr = event.pullRequest;
      let assessment = await this.prisma.pullRequestSecurityAssessment.findFirst({
        where: { workspaceId, repositoryId: repository.id as string, prNumber: pr.number, headCommit: pr.headCommit },
      }) as Row | null;
      if (!assessment) {
        assessment = await this.prisma.pullRequestSecurityAssessment.create({
          data: {
            workspaceId, integrationId: verifiedIntegrationId, repositoryId: repository.id as string,
            provider, prNumber: pr.number,
            title: sanitizeUntrustedText(pr.title),
            baseBranch: pr.baseBranch ?? null, headBranch: pr.headBranch ?? null,
            baseCommit: pr.baseCommit ?? null, headCommit: pr.headCommit,
            scanStatus: "PENDING",
          },
        }) as Row;
      }
      const outcome = await this.triggers.triggerRepositoryScan({
        workspaceId, repository, actorUserId: link.createdBy as string, purpose: `${provider.toLowerCase()}.pull_request`,
      });
      const updated = await this.prisma.pullRequestSecurityAssessment.update({
        where: { id: assessment.id as string },
        data: outcome.started
          ? { scanId: outcome.scanId, scanStatus: "RUNNING" }
          : { scanStatus: "BLOCKED", blockReason: outcome.reasonCode },
      });
      await this.finishRecord(recordRow, outcome.started ? "PROCESSED" : "BLOCKED", outcome.reasonCode ?? null);
      return {
        status: outcome.started ? "PROCESSED" : "BLOCKED",
        reasonCode: outcome.reasonCode, detail: outcome.detail,
        assessmentId: updated.id as string, scanId: outcome.scanId, httpStatus: 200,
      };
    }

    await this.finishRecord(recordRow, "IGNORED", `EVENT_KIND_${event.kind}`);
    return { status: "IGNORED", detail: `event kind ${event.kind} recorded; no automation configured for it`, httpStatus: 200 };
  }

  /** §19/§21: finalize a PR assessment once its scan is terminal —
   *  classify findings against the baseline, evaluate the gate, and
   *  record the concise check-publish outcome (never fabricated). */
  async completePullRequestAssessment(workspaceId: string, assessmentId: string, actorId: string) {
    const assessment = await this.prisma.pullRequestSecurityAssessment.findFirst({
      where: { id: assessmentId, workspaceId },
    }) as Row | null;
    if (!assessment) return null;
    if (!assessment.scanId) return assessment;
    const scan = await this.prisma.scan.findFirst({ where: { id: assessment.scanId, workspaceId } });
    if (!scan || !["COMPLETED", "FAILED", "CANCELLED"].includes(scan.status as string)) return assessment;
    const policy = await this.prisma.repositorySecurityPolicy.findFirst({
      where: { workspaceId, sourceRepositoryId: assessment.repositoryId as string },
    }) as Row | null;
    const gate = await this.gates.evaluateForScan({
      workspaceId,
      repositoryId: assessment.repositoryId as string,
      scanId: assessment.scanId as string,
      context: "PR_ASSESSMENT",
      pullRequestAssessmentId: assessmentId,
      gatePolicyId: policy?.gatePolicyId as string | undefined,
      prGatePreset: policy?.prGatePreset as string | undefined,
      actorId,
    });
    const evalSummary = ((gate.evaluation as Row).summary ?? {}) as Row;
    const updated = await this.prisma.pullRequestSecurityAssessment.update({
      where: { id: assessmentId },
      data: {
        scanStatus: scan.status === "COMPLETED" ? "COMPLETED" : "FAILED",
        gateResult: gate.result,
        gateEvaluationId: (gate.evaluation as Row).id as string,
        newFindings: gate.newFindingIds,
        resolvedFindings: (evalSummary.resolvedFindingIds as string[]) ?? [],
        regressedFindings: (evalSummary.regressedFindingIds as string[]) ?? [],
        // Check publishing goes through the provider connector; with
        // no transport wired it honestly stays NOT_CONFIGURED (§21).
        checkPublished: "NOT_CONFIGURED",
      },
    });
    await this.audit.record({
      actorId, workspaceId,
      action: "PR_SECURITY_SCAN_COMPLETED", resourceType: "PullRequestSecurityAssessment", resourceId: assessmentId,
      metadata: { gateResult: gate.result, newTotal: gate.summary.newTotal },
    }).catch(() => undefined);
    return updated;
  }

  private fallbackDeliveryId(provider: string, rawBody: string): string {
    // Providers without a delivery-id header (older GitLab): the
    // idempotency key is a digest of the exact body — a byte-identical
    // redelivery dedupes, a different payload does not.
    return `${provider.toLowerCase()}-body-${createHash("sha256").update(rawBody).digest("hex").slice(0, 32)}`;
  }

  private async record(
    workspaceId: string | null, integrationId: string | null, provider: string,
    deliveryId: string, eventType: string, signatureStatus: string,
    processingStatus: string, detail: string | null,
  ): Promise<Row> {
    return (await this.prisma.inboundIntegrationEvent.create({
      data: {
        workspaceId, integrationId, provider, deliveryId, eventType,
        signatureStatus, processingStatus, detail,
      },
    })) as Row;
  }

  private async finishRecord(row: Row | null, processingStatus: string, detail: string | null): Promise<void> {
    if (!row) return;
    await this.prisma.inboundIntegrationEvent.update({
      where: { id: row.id as string },
      data: { processingStatus, detail },
    }).catch(() => undefined);
  }
}
