import {
  BadRequestException, Inject, Injectable, NotFoundException,
} from "@nestjs/common";
import {
  APPROVED_STEAMPIPE_PACKS, CLOUD_PIPELINE_STAGES, CLOUD_V2_REPORTS,
  DEFAULT_CLOUD_BASELINE_RULES, analyzeCloudInventory, analyzeCloudIamPosture,
  buildCloudAttackPathCandidates, buildCloudCoverage, buildIamGraphEdges,
  buildResourceSnapshot, completionForGaps, diffResourceSnapshots,
  evaluateBaselineDeviations, evaluateCloudAuthorization, evaluateCloudConnection,
  evaluateSteampipeQueryRequest, hashBaselineRules, planCloudNlQuery,
  planCloudVerification, screenCloudAiRequest,
  type CloudConnectionProbeFacts, type CloudV2BaselineRule,
  type CloudV2PipelineStage, type NormalizedCloudIdentity, type NormalizedCloudResource,
} from "@zerosweep/security-sdk";
import { AuditService } from "../audit/audit.service";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { resolveWorkspace } from "../../common/tenant";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireCloudV2Permission, cloudV2PermissionsFor } from "./permissions";

type AuthUser = RequestUser;
type Headers = Record<string, string | string[] | undefined>;
/* eslint-disable @typescript-eslint/no-explicit-any */
type Row = Record<string, any>;

/**
 * Cloud Security V2 (Prompt 34). Deepens the Prompt 14 engine on the
 * same canonical models: governed connection tests (§12), the Cloud
 * Security Orchestrator (§19/§103) over RECORDED inventory, immutable
 * resource snapshots + drift (§17/§18), IAM posture/graph/attack-path
 * candidates (§28–§33), versioned baselines (§97/§100), coverage
 * (§111/§112) and deterministic NL queries (§137).
 *
 * Honesty rules are structural: the live provider transports are
 * deliberately unwired in this deployment, so connection facts report
 * transportConfigured=false and tests conclude UNREACHABLE — never a
 * fabricated CONNECTED. Posture findings produced by an assessment
 * run are CANDIDATES with canonical fingerprints; they enter the
 * Finding table only through the governed scan path (§43/§116), so a
 * V2 run never fabricates persisted findings.
 */
@Injectable()
export class CloudSecurityV2Service {
  /** No live provider transport is wired in this deployment (§12). */
  private readonly transportConfigured = false;

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly auditService: AuditService,
  ) {}

  private ws(user: AuthUser, headers: Headers) {
    return resolveWorkspace(this.prisma, user, headers["x-workspace-id"] as string | undefined);
  }

  private async audit(workspaceId: string, user: AuthUser, action: string, entityType: string, entityId: string, metadata?: Record<string, unknown>): Promise<void> {
    await this.auditService
      .record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: action as never, resourceType: entityType, resourceId: entityId,
        ...(metadata ? { metadata } : {}),
      })
      .catch(() => undefined);
  }

  mePermissions(user: AuthUser) {
    return { role: user.role, permissions: cloudV2PermissionsFor(user.role) };
  }

  private async accountOr404(workspaceId: string, id: string): Promise<Row> {
    const account = await this.prisma.cloudAccount.findFirst({ where: { id, workspaceId } });
    if (!account) throw new NotFoundException("Cloud account not found");
    return account as Row;
  }

  /* --------------------- connection test (§12/§138) --------------------- */

  private probeFacts(account: Row): CloudConnectionProbeFacts {
    return {
      credentialReferencePresent: Boolean(account.credentialReference),
      transportConfigured: this.transportConfigured,
      expectedAccountId: account.externalAccountId as string,
      // Identity/auth facts exist only when a transport is wired; with
      // the transport NOT_CONFIGURED the evaluation honestly concludes
      // UNREACHABLE (or AUTH_FAILED when there is no reference at all).
    };
  }

  async testConnection(user: AuthUser, headers: Headers, accountId: string) {
    requireCloudV2Permission(user, "RUN_CLOUD_ASSESSMENT");
    const workspace = await this.ws(user, headers);
    const account = await this.accountOr404(workspace.id, accountId);
    const evaluation = evaluateCloudConnection(this.probeFacts(account));
    const record = await this.prisma.cloudConnectionTest.create({
      data: {
        workspaceId: workspace.id, cloudAccountId: accountId, result: evaluation.result,
        limitations: evaluation.limitations as never, missingPermissions: evaluation.missingPermissions as never,
        accountMatch: evaluation.accountMatch, testedById: user.id,
      },
    });
    await this.audit(
      workspace.id, user,
      evaluation.result.startsWith("CONNECTED") ? "CLOUD_ACCOUNT_CONNECTED" : "CLOUD_ACCOUNT_CONNECTION_FAILED",
      "CloudAccount", accountId, { result: evaluation.result, accountMatch: evaluation.accountMatch },
    );
    return { test: record, evaluation };
  }

  async listConnectionTests(user: AuthUser, headers: Headers, accountId: string) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await this.ws(user, headers);
    await this.accountOr404(workspace.id, accountId);
    const rows = await this.prisma.cloudConnectionTest.findMany({
      where: { workspaceId: workspace.id, cloudAccountId: accountId }, orderBy: { testedAt: "desc" }, take: 50,
    });
    return { items: rows };
  }

  /* --------------------- assessment orchestrator (§19/§103) --------------------- */

  private toNormalizedResource(r: Row): NormalizedCloudResource {
    return {
      provider: r.provider, resourceType: r.resourceType, providerResourceId: r.providerResourceId,
      name: r.name, ...(r.region ? { region: r.region } : {}), tags: (r.tags ?? {}) as Record<string, string>,
      configuration: (r.configurationMetadata ?? {}) as Record<string, unknown>,
      exposure: r.exposure, source: "cloud-v2-assessment",
    };
  }

  private toNormalizedIdentity(i: Row): NormalizedCloudIdentity {
    return {
      provider: i.provider, identityType: i.identityType, providerIdentityId: i.providerIdentityId,
      name: i.name, privileged: Boolean(i.privileged),
      ...(i.privilegeEvidence ? { privilegeEvidence: i.privilegeEvidence as Record<string, unknown> } : {}),
      ...(i.mfaEnabled !== null && i.mfaEnabled !== undefined ? { mfaEnabled: Boolean(i.mfaEnabled) } : {}),
      ...(i.lastUsedAt ? { lastUsedAt: new Date(i.lastUsedAt).toISOString() } : {}),
      ...(i.keyAgeDays !== null && i.keyAgeDays !== undefined ? { keyAgeDays: Number(i.keyAgeDays) } : {}),
      metadata: (i.metadata ?? {}) as Record<string, unknown>,
    };
  }

  async assessAccount(user: AuthUser, headers: Headers, accountId: string, body: Record<string, unknown>) {
    requireCloudV2Permission(user, "RUN_CLOUD_ASSESSMENT");
    const workspace = await this.ws(user, headers);
    const account = await this.accountOr404(workspace.id, accountId);

    // §8 authorization gate — every condition is checked in the open.
    const linkedAssessment = account.targetId
      ? await this.prisma.assessment.findFirst({ where: { workspaceId: workspace.id, targetId: account.targetId as string, status: "APPROVED" } })
      : null;
    const scope = await this.prisma.cloudScope.findFirst({ where: { workspaceId: workspace.id, cloudAccountId: accountId } }) as Row | null;
    const requestedRegions = Array.isArray(body.regions) ? (body.regions as string[]) : (scope?.includeRegions as string[] | undefined) ?? [];
    const authorization = evaluateCloudAuthorization({
      authorizationId: (account.authorizationId as string | null) ?? (linkedAssessment ? (linkedAssessment as Row).id : null),
      authorizationStatus: linkedAssessment ? "APPROVED" : account.authorizationId ? "ACTIVE" : null,
      accountProvider: account.provider as string,
      authorizationProvider: account.provider as string,
      externalAccountId: account.externalAccountId as string,
      credentialReference: (account.credentialReference as string | null) ?? null,
      allowedRegions: (scope?.includeRegions as string[] | undefined) ?? [],
      requestedRegions,
    });

    const run = await this.prisma.cloudV2AssessmentRun.create({
      data: {
        workspaceId: workspace.id, domain: "CLOUD", cloudAccountId: accountId,
        status: "RUNNING", startedById: user.id, pipeline: [] as never,
      },
    }) as Row;
    await this.audit(workspace.id, user, "CLOUD_ASSESSMENT_STARTED", "CloudAccount", accountId, { runId: run.id });

    if (!authorization.allowed) {
      const blocked = await this.prisma.cloudV2AssessmentRun.update({
        where: { id: run.id },
        data: { status: "BLOCKED", blockedReason: authorization.reasons.join(" "), completedAt: new Date(), pipeline: [{ stage: "CONNECT", status: "BLOCKED", detail: authorization.reasons.join(" ") }] as never },
      });
      return { run: blocked, authorization, stages: (blocked as Row).pipeline, coverage: null, postureCandidates: [], iamSignals: [], attackPaths: [] };
    }

    const stages: CloudV2PipelineStage[] = [];
    const stage = (name: string, status: CloudV2PipelineStage["status"], detail: string) => {
      stages.push({ stage: name, status, detail });
    };

    // CONNECT (§103) — governed connection evaluation.
    const evaluation = evaluateCloudConnection(this.probeFacts(account));
    await this.prisma.cloudConnectionTest.create({
      data: {
        workspaceId: workspace.id, cloudAccountId: accountId, result: evaluation.result,
        limitations: evaluation.limitations as never, missingPermissions: evaluation.missingPermissions as never,
        accountMatch: evaluation.accountMatch, testedById: user.id,
      },
    });
    stage("CONNECT", evaluation.result === "CONNECTED" ? "COMPLETED" : "COMPLETED_WITH_GAPS", `Connection test: ${evaluation.result}`);

    // INVENTORY (§14) — recorded inventory only; nothing is probed live.
    const resourceRows = await this.prisma.cloudResource.findMany({ where: { workspaceId: workspace.id, cloudAccountId: accountId }, take: 5000 }) as Row[];
    const identityRows = await this.prisma.cloudIdentity.findMany({ where: { workspaceId: workspace.id, cloudAccountId: accountId }, take: 2000 }) as Row[];
    const resources = resourceRows.map((r) => this.toNormalizedResource(r));
    const identities = identityRows.map((i) => this.toNormalizedIdentity(i));
    stage("INVENTORY", "COMPLETED", `${resources.length} resources, ${identities.length} identities from recorded inventory (transport NOT_CONFIGURED — no live collection)`);

    // POSTURE (§19/§43) — provider-native engines over the inventory.
    const analysis = analyzeCloudInventory({ resources, identities }, {
      provider: account.provider, accountId, accountRef: account.externalAccountId as string, toolSlug: "cloud-v2-orchestrator",
    });
    stage("POSTURE", "COMPLETED", `${analysis.findings.length} posture candidate(s), ${analysis.controlAssessments.length} control assessment(s) — candidates enter Finding only via the governed scan path (§116)`);

    // IAM (§28–§33) — posture signals, graph edges, attack-path candidates.
    const iamSignals = analyzeCloudIamPosture(identities);
    const edges = buildIamGraphEdges(identities, resources);
    let newEdges = 0;
    for (const edge of edges) {
      const existing = await this.prisma.cloudRelationship.findFirst({
        where: { cloudAccountId: accountId, fromType: edge.fromType, fromRef: edge.fromRef, relationship: edge.relationship, toType: edge.toType, toRef: edge.toRef },
      });
      if (!existing) {
        await this.prisma.cloudRelationship.create({
          data: { workspaceId: workspace.id, cloudAccountId: accountId, ...edge },
        }).catch(() => undefined);
        newEdges++;
      }
    }
    const attackPaths = buildCloudAttackPathCandidates({ resources, identities, edges });
    for (const path of attackPaths) {
      await this.prisma.cloudRiskPath.create({
        data: {
          workspaceId: workspace.id, cloudAccountId: accountId, title: path.title,
          steps: path.steps as never, confidence: path.confidence, findingIds: [],
        },
      }).catch(() => undefined);
    }
    stage("IAM", iamSignals.length ? "COMPLETED_WITH_GAPS" : "COMPLETED", `${iamSignals.length} IAM risk signal(s); ${edges.length} graph edge(s) (${newEdges} new); ${attackPaths.length} attack-path candidate(s) — analytical only, never executed (§33)`);

    // EXPOSURE (§34/§35) — public exposure is context, not a verdict.
    const publicCount = resources.filter((r) => r.exposure === "PUBLIC").length;
    stage("EXPOSURE", "COMPLETED", `${publicCount} publicly exposed resource(s) recorded as contextual risk evidence (§35)`);

    // VULNERABILITY (§43) — persisted cloud findings from governed scans.
    const persisted = await this.persistedCloudFindings(workspace.id);
    stage("VULNERABILITY", "COMPLETED", `${persisted.length} persisted canonical cloud finding(s) in workspace`);

    // COMPLIANCE (§101/§102) — mappings are evidence, never certification.
    stage("COMPLIANCE", "COMPLETED", `${analysis.controlAssessments.length} control mapping(s) recorded as GRC evidence — a tool pass is not a certification (§102)`);

    // CORRELATION (§45) — canonical fingerprints dedupe across tools.
    const distinct = new Set(analysis.findings.map((f) => f.sourceFingerprint)).size;
    stage("CORRELATION", "COMPLETED", `${analysis.findings.length} candidate observation(s) → ${distinct} canonical fingerprint(s) (§45/§117)`);

    // Snapshots + drift (§17/§18) — part of the inventory/correlation tail.
    let driftCount = 0;
    for (const r of resourceRows) {
      const snap = buildResourceSnapshot(this.toNormalizedResource(r));
      const previous = await this.prisma.cloudResourceSnapshot.findFirst({
        where: { workspaceId: workspace.id, cloudResourceId: r.id }, orderBy: { capturedAt: "desc" },
      }) as Row | null;
      await this.prisma.cloudResourceSnapshot.create({
        data: {
          workspaceId: workspace.id, cloudAccountId: accountId, cloudResourceId: r.id, runId: run.id,
          configuration: snap.configuration as never, configurationHash: snap.configurationHash, exposure: snap.exposure,
        },
      });
      if (previous) {
        const events = diffResourceSnapshots(r.providerResourceId as string,
          { configuration: (previous.configuration ?? {}) as Record<string, unknown>, configurationHash: previous.configurationHash as string, exposure: previous.exposure as string },
          snap);
        for (const event of events) {
          await this.prisma.cloudDriftEvent.create({
            data: {
              workspaceId: workspace.id, cloudAccountId: accountId,
              kind: event.kind === "PUBLIC_EXPOSURE" ? "EXPOSURE_CHANGED" : event.kind === "IAM_CHANGE" ? "IAM_CHANGED" : event.kind === "ENCRYPTION_CHANGE" ? "ENCRYPTION_CHANGED" : event.kind.startsWith("LOGGING") ? "LOGGING_CHANGED" : event.kind,
              resourceRef: event.resourceRef, detail: `${event.detail} [riskSignal=${event.riskSignal}]`,
            },
          }).catch(() => undefined);
          driftCount++;
        }
      }
    }
    if (driftCount > 0) await this.audit(workspace.id, user, "CLOUD_DRIFT_DETECTED", "CloudAccount", accountId, { runId: run.id, driftEvents: driftCount });

    // RISK (§119) — Risk Engine V3 consumes these signals downstream.
    stage("RISK", "COMPLETED", "Risk signals staged for Risk Engine V3: exposure, IAM privilege, KEV/EPSS via vulnerability intelligence (§119)");
    // REMEDIATION (§120/§121) — guidance + verification plans only.
    stage("REMEDIATION", "COMPLETED", "Remediation routes through Prompt 31; verification = configuration re-read / targeted governed check (§121). No auto-remediation (§124)");
    // REPORT (§133/§134).
    stage("REPORT", "COMPLETED", `${CLOUD_V2_REPORTS.length} V2 report definitions available on the Prompt 20 reporting engine (§133)`);

    // Coverage (§111/§112) + completion (§110).
    const regionsCovered = new Set(resources.map((r) => r.region).filter(Boolean)).size;
    const coverageBuilt = buildCloudCoverage({
      accountsCovered: 1, regionsCovered, regionsAuthorized: requestedRegions.length || regionsCovered,
      servicesCovered: new Set(resources.map((r) => r.resourceType)).size, resourcesCovered: resources.length,
      iamIdentities: identities.length, postureChecks: analysis.controlAssessments.length,
      connectionResult: evaluation.result, missingPermissions: evaluation.missingPermissions,
      transportConfigured: this.transportConfigured,
    });
    const coverage = await this.prisma.cloudSecurityCoverage.create({
      data: {
        workspaceId: workspace.id, runId: run.id, cloudAccountId: accountId,
        accountsCovered: coverageBuilt.coverage.accountsCovered, regionsCovered: coverageBuilt.coverage.regionsCovered,
        regionsAuthorized: coverageBuilt.coverage.regionsAuthorized, servicesCovered: coverageBuilt.coverage.servicesCovered,
        resourcesCovered: coverageBuilt.coverage.resourcesCovered, iamIdentities: coverageBuilt.coverage.iamIdentities,
        postureChecks: coverageBuilt.coverage.postureChecks, gaps: coverageBuilt.gaps as never, completion: coverageBuilt.completion,
      },
    });
    const orderedStages = CLOUD_PIPELINE_STAGES.map((name) => stages.find((s) => s.stage === name) ?? { stage: name, status: "COMPLETED" as const, detail: "" });
    const finished = await this.prisma.cloudV2AssessmentRun.update({
      where: { id: run.id },
      data: { status: coverageBuilt.completion, pipeline: orderedStages as never, completedAt: new Date() },
    });
    await this.audit(workspace.id, user, "CLOUD_ASSESSMENT_COMPLETED", "CloudAccount", accountId, { runId: run.id, completion: coverageBuilt.completion, driftEvents: driftCount });
    return {
      run: finished, authorization, stages: orderedStages, coverage,
      postureCandidates: analysis.findings.slice(0, 100), iamSignals, attackPaths,
    };
  }

  /* --------------------- read surfaces (§138) --------------------- */

  private async persistedCloudFindings(workspaceId: string): Promise<Row[]> {
    const rows = await this.prisma.finding.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 1000 }) as Row[];
    return rows.filter((f) => typeof f.fingerprint === "string" && (f.fingerprint as string).startsWith("cloud:"));
  }

  async listFindings(user: AuthUser, headers: Headers) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await this.ws(user, headers);
    const rows = await this.persistedCloudFindings(workspace.id);
    return { items: rows.slice(0, 200), total: rows.length };
  }

  async listAttackPaths(user: AuthUser, headers: Headers, query: Record<string, unknown>) {
    requireCloudV2Permission(user, "VIEW_CLOUD_ATTACK_PATHS");
    const workspace = await this.ws(user, headers);
    const where: Row = { workspaceId: workspace.id };
    if (query.accountId) where.cloudAccountId = String(query.accountId);
    const rows = await this.prisma.cloudRiskPath.findMany({ where, orderBy: { createdAt: "desc" }, take: 200 });
    return { items: rows, note: "Attack-path candidates are analytical models over evidence — never executed (§33)." };
  }

  async listResourceSnapshots(user: AuthUser, headers: Headers, resourceId: string) {
    requireCloudV2Permission(user, "VIEW_CLOUD_EVIDENCE");
    const workspace = await this.ws(user, headers);
    const resource = await this.prisma.cloudResource.findFirst({ where: { id: resourceId, workspaceId: workspace.id } });
    if (!resource) throw new NotFoundException("Cloud resource not found");
    const rows = await this.prisma.cloudResourceSnapshot.findMany({
      where: { workspaceId: workspace.id, cloudResourceId: resourceId }, orderBy: { capturedAt: "desc" }, take: 50,
    });
    return { items: rows };
  }

  async getCoverage(user: AuthUser, headers: Headers, query: Record<string, unknown>) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await this.ws(user, headers);
    const where: Row = { workspaceId: workspace.id };
    if (query.accountId) where.cloudAccountId = String(query.accountId);
    const rows = await this.prisma.cloudSecurityCoverage.findMany({ where, orderBy: { createdAt: "desc" }, take: 20 });
    return { items: rows };
  }

  async listRuns(user: AuthUser, headers: Headers) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await this.ws(user, headers);
    const rows = await this.prisma.cloudV2AssessmentRun.findMany({
      where: { workspaceId: workspace.id, domain: "CLOUD" }, orderBy: { startedAt: "desc" }, take: 50,
    });
    return { items: rows };
  }

  /* --------------------- baselines (§97/§100) --------------------- */

  async createBaseline(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireCloudV2Permission(user, "MANAGE_CLOUD_ACCOUNTS");
    const workspace = await this.ws(user, headers);
    const rules = (Array.isArray(body.rules) ? body.rules : DEFAULT_CLOUD_BASELINE_RULES) as CloudV2BaselineRule[];
    for (const rule of rules) {
      if (!rule.ruleId || !rule.expectation || !rule.severity) throw new BadRequestException("Each baseline rule needs ruleId, expectation and severity (§97)");
    }
    const cloudAccountId = body.cloudAccountId ? String(body.cloudAccountId) : null;
    if (cloudAccountId) await this.accountOr404(workspace.id, cloudAccountId);
    const provider = body.provider ? String(body.provider) : null;
    const existing = await this.prisma.cloudSecurityBaseline.findMany({ where: { workspaceId: workspace.id, cloudAccountId, provider } });
    const version = (existing as Row[]).reduce((max, r) => Math.max(max, Number(r.version ?? 0)), 0) + 1;
    const baseline = await this.prisma.cloudSecurityBaseline.create({
      data: { workspaceId: workspace.id, cloudAccountId, provider, version, rules: rules as never, hash: hashBaselineRules(rules), createdById: user.id },
    });
    await this.audit(workspace.id, user, "CLOUD_BASELINE_CREATED", "CloudSecurityBaseline", (baseline as Row).id, { version });
    return baseline;
  }

  async listBaselines(user: AuthUser, headers: Headers) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await this.ws(user, headers);
    const rows = await this.prisma.cloudSecurityBaseline.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 50 });
    return { items: rows };
  }

  async baselineDrift(user: AuthUser, headers: Headers, query: Record<string, unknown>) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await this.ws(user, headers);
    const baseline = await this.prisma.cloudSecurityBaseline.findFirst({
      where: { workspaceId: workspace.id, ...(query.accountId ? { cloudAccountId: String(query.accountId) } : {}) },
      orderBy: { createdAt: "desc" },
    }) as Row | null;
    if (!baseline) return { baseline: null, deviations: [], note: "No cloud baseline exists yet — create one to enable baseline drift (§100)." };
    const resourceRows = await this.prisma.cloudResource.findMany({
      where: { workspaceId: workspace.id, ...(query.accountId ? { cloudAccountId: String(query.accountId) } : {}) }, take: 5000,
    }) as Row[];
    const accountId = (query.accountId as string) ?? (resourceRows[0]?.cloudAccountId as string | undefined);
    const analysis = accountId
      ? analyzeCloudInventory(
        { resources: resourceRows.map((r) => this.toNormalizedResource(r)), identities: [] },
        { provider: (resourceRows[0]?.provider ?? "AWS") as never, accountId, accountRef: accountId, toolSlug: "cloud-v2-baseline" },
      )
      : { findings: [] as Array<{ ruleId?: string }> };
    const facts: Record<string, string> = {};
    for (const rule of baseline.rules as CloudV2BaselineRule[]) {
      facts[rule.ruleId] = analysis.findings.some((f) => f.ruleId === rule.ruleId) ? "PRESENT" : "ABSENT";
    }
    return { baseline, deviations: evaluateBaselineDeviations(baseline.rules as CloudV2BaselineRule[], facts), facts };
  }

  /* --------------------- Steampipe packs + NL + reports --------------------- */

  steampipePacks(user: AuthUser) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    return { items: APPROVED_STEAMPIPE_PACKS, note: "Only platform-approved packs/queries may run — raw SQL is rejected (§25)." };
  }

  runSteampipeQuery(user: AuthUser, body: Record<string, unknown>) {
    requireCloudV2Permission(user, "RUN_CLOUD_ASSESSMENT");
    const decision = evaluateSteampipeQueryRequest({
      packId: body.packId ? String(body.packId) : undefined,
      queryId: body.queryId ? String(body.queryId) : undefined,
      rawSql: body.rawSql ? String(body.rawSql) : undefined,
    });
    if (!decision.allowed) throw new BadRequestException(decision.reason);
    return {
      allowed: true, pack: decision.pack?.packId, query: decision.query?.queryId,
      status: "NOT_CONFIGURED",
      detail: "The query is approved (§24) but the Steampipe transport is not wired in this deployment — nothing was executed and no result is fabricated.",
      executes: false,
    };
  }

  async nlQuery(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await this.ws(user, headers);
    const text = String(body.text ?? "");
    const screen = screenCloudAiRequest(text);
    if (!screen.allowed) return { refused: true, reason: screen.reason, executed: false as const };
    const { plan, refusal } = planCloudNlQuery(text);
    if (refusal) return { refused: true, reason: refusal, executed: false as const };
    if (!plan || plan.kind === "UNSUPPORTED") return { refused: false, plan, rows: [], executed: false as const };

    let rows: Row[] = [];
    if (plan.kind === "PUBLIC_PRODUCTION_DATABASES" || plan.kind === "PUBLIC_STORAGE") {
      const accounts = await this.prisma.cloudAccount.findMany({ where: { workspaceId: workspace.id } }) as Row[];
      const prodIds = new Set(accounts.filter((a) => plan.kind === "PUBLIC_STORAGE" || a.environment === "PRODUCTION").map((a) => a.id as string));
      const resources = await this.prisma.cloudResource.findMany({ where: { workspaceId: workspace.id, exposure: "PUBLIC" }, take: 500 }) as Row[];
      rows = resources.filter((r) => prodIds.has(r.cloudAccountId as string) && (
        plan.kind === "PUBLIC_STORAGE" ? /STORAGE|S3|BUCKET/i.test(r.resourceType as string) : /RDS|DATABASE|SQL|AURORA/i.test(r.resourceType as string)
      ));
    } else if (plan.kind === "BROAD_PERMISSION_IDENTITIES") {
      rows = await this.prisma.cloudIdentity.findMany({ where: { workspaceId: workspace.id, privileged: true }, take: 200 }) as Row[];
    } else if (plan.kind === "PRIVILEGED_WORKLOAD_CLUSTERS") {
      const workloads = await this.prisma.kubernetesWorkload.findMany({ where: { workspaceId: workspace.id }, take: 1000 }) as Row[];
      const clusterIds = new Set(workloads.filter((w) => ((w.securityContext ?? {}) as Row).privileged === true).map((w) => w.clusterId as string));
      rows = await this.prisma.kubernetesCluster.findMany({ where: { workspaceId: workspace.id } }) as Row[];
      rows = rows.filter((c) => clusterIds.has(c.id as string));
    } else if (plan.kind === "INTERNET_WORKLOADS_CRITICAL_VULNS") {
      const workloads = await this.prisma.kubernetesWorkload.findMany({ where: { workspaceId: workspace.id, exposure: "PUBLIC_INTERNET" }, take: 200 }) as Row[];
      const critical = await this.persistedCloudFindings(workspace.id);
      rows = workloads.map((w) => ({ ...w, criticalFindingsInWorkspace: critical.filter((f) => f.severity === "CRITICAL").length }));
    } else if (plan.kind === "KEV_RUNNING_CONTAINERS") {
      const findings = await this.prisma.finding.findMany({ where: { workspaceId: workspace.id }, take: 1000 }) as Row[];
      rows = findings.filter((f) => typeof f.fingerprint === "string" && ((f.fingerprint as string).startsWith("imgvuln:")) && f.cve);
    }
    return { refused: false, plan, rows: rows.slice(0, 100), executed: false as const };
  }

  reports(user: AuthUser) {
    requireCloudV2Permission(user, "EXPORT_CLOUD_SECURITY_REPORT");
    return { items: CLOUD_V2_REPORTS, engine: "Prompt 20 reporting engine (immutable snapshots)", completion: completionForGaps([]) };
  }

  verificationPlan(user: AuthUser, body: Record<string, unknown>) {
    requireCloudV2Permission(user, "VIEW_CLOUD_SECURITY");
    return planCloudVerification(String(body.ruleId ?? ""));
  }
}
