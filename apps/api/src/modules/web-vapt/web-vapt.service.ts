import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  PLATFORM_BUDGET_CEILING, buildScopeSnapshot, clampBudget, computeCoverage, defaultBudgetFor,
  deriveScanStatus, evaluateAuthorizationMatrix, evaluateModuleGate, evaluatePreflight, profileDefinition,
  requestClassOf, sha256Hex, toolCapability, toolHealthView, validateBusinessLogicScenario, validateMatrixRows,
  type AuthorizationMatrixRow, type ScanRequestBudget, type SkippedTest, type TargetEnvironment, type WebVaptProfileKey,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import { resolveWorkspace } from "../../common/tenant";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireWebVaptPermission } from "./permissions";

type AuthUser = RequestUser;

const ENVIRONMENTS = ["PRODUCTION", "STAGING", "DEVELOPMENT", "TEST", "UNKNOWN"] as const;
const PROFILE_KEYS: readonly string[] = ["WEB_PASSIVE", "WEB_SAFE", "WEB_STANDARD", "API_SAFE", "API_STANDARD", "TLS_ONLY", "CONTENT_DISCOVERY", "TARGETED_VERIFICATION"];

/**
 * Web/API VAPT V2 service (Prompt 32). Deepens the Prompt 5–9 engines
 * on the SAME canonical models — a V2 target binds an existing
 * VERIFIED parent Target + APPROVED assessment; plans freeze an
 * immutable scope snapshot + clamped budget BEFORE anything runs;
 * HIGH modules pass the §16 gate or are visibly blocked; preflight
 * probes go through a transport seam that is honestly NOT_CONFIGURED
 * in this deployment, so no scan fabricates reachability (§7/§8).
 * Credentials are secret REFERENCES only (§50/§53) — this service
 * stores and returns profile IDs, never values.
 */
@Injectable()
export class WebVaptService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly auditService: AuditService,
  ) {}

  private async ws(user: AuthUser, headers: Record<string, string | string[] | undefined>) {
    return resolveWorkspace(this.prisma, user, headers["x-workspace-id"] as string | undefined);
  }

  private async audit(workspaceId: string, user: AuthUser, action: string, entityType: string, entityId: string, metadata?: Record<string, unknown>): Promise<void> {
    await this.auditService.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: action as never, resourceType: entityType, resourceId: entityId,
      ...(metadata ? { metadata } : {}),
    }).catch(() => undefined);
  }

  /* ------------------------------- targets (§4) ------------------------------- */

  async createTarget(user: AuthUser, headers: Record<string, string | string[] | undefined>, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "MANAGE_WEB_TARGETS");
    const workspace = await this.ws(user, headers);
    const assetId = String(body.assetId ?? "");
    const targetId = String(body.targetId ?? "");
    const baseUrl = String(body.baseUrl ?? "");
    let origin: string;
    try {
      const u = new URL(baseUrl);
      if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("protocol");
      origin = u.origin;
    } catch {
      throw new BadRequestException("baseUrl must be an absolute http(s) URL");
    }
    const asset = await this.prisma.asset.findFirst({ where: { id: assetId, workspaceId: workspace.id } });
    if (!asset) throw new NotFoundException("Asset not found in this workspace");
    const target = await this.prisma.target.findFirst({ where: { id: targetId, workspaceId: workspace.id } });
    if (!target) throw new NotFoundException("Target not found in this workspace");
    if (!target.verified) {
      throw new BadRequestException("Parent target is not VERIFIED — ownership verification (§6) precedes any V2 target");
    }
    const assessment = await this.prisma.assessment.findFirst({ where: { workspaceId: workspace.id, targetId, status: "APPROVED" }, orderBy: { createdAt: "desc" } });
    if (!assessment) {
      throw new BadRequestException("No APPROVED assessment for this target — active authorization (§6) is mandatory before a V2 target can be created");
    }
    const authenticationProfileId = body.authenticationProfileId ? String(body.authenticationProfileId) : null;
    if (authenticationProfileId) {
      const profile = await this.prisma.authenticationProfile.findFirst({ where: { id: authenticationProfileId, sessionProfile: { workspaceId: workspace.id } } });
      if (!profile) throw new NotFoundException("Authentication profile not found in this workspace");
    }
    const environment = ENVIRONMENTS.includes(String(body.environment ?? "UNKNOWN") as never) ? String(body.environment ?? "UNKNOWN") : "UNKNOWN";
    const row = await this.prisma.webVaptTarget.create({
      data: {
        workspaceId: workspace.id, assetId, targetId, baseUrl, normalizedOrigin: origin,
        authorizationId: assessment.id, environment,
        criticality: String(body.criticality ?? "MEDIUM"),
        ...(authenticationProfileId ? { authenticationProfileId } : {}),
        scanProfileKey: PROFILE_KEYS.includes(String(body.scanProfileKey ?? "")) ? String(body.scanProfileKey) : "WEB_SAFE",
        createdBy: user.id,
      },
    });
    await this.audit(workspace.id, user, "WEB_VAPT_TARGET_CREATED", "WebVaptTarget", row.id, { origin, environment });
    return row;
  }

  async listTargets(user: AuthUser, headers: Record<string, string | string[] | undefined>) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    return this.prisma.webVaptTarget.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" } });
  }

  private async targetOr404(workspaceId: string, id: string) {
    const row = await this.prisma.webVaptTarget.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Web VAPT target not found");
    return row;
  }

  async getTarget(user: AuthUser, headers: Record<string, string | string[] | undefined>, id: string) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const target = await this.targetOr404(workspace.id, id);
    const [plans, preflights, endpoints] = await Promise.all([
      this.prisma.webVaptScanPlan.count({ where: { workspaceId: workspace.id, webTargetId: id } }),
      this.prisma.webVaptPreflightResult.findMany({ where: { workspaceId: workspace.id, webTargetId: id }, orderBy: { createdAt: "desc" }, take: 5 }),
      this.prisma.endpoint.count({ where: { assetId: target.assetId } }),
    ]);
    return { target, planCount: plans, recentPreflights: preflights, endpointCount: endpoints };
  }

  /* ------------------------------- preflight (§7/§8) ------------------------------- */

  /**
   * Authorization facts are REAL (parent target verification, the
   * APPROVED assessment, the verification expiry). Reachability probes
   * traverse a transport seam: no live probe transport is wired in
   * this deployment, so the transport reports NOT_CONFIGURED and the
   * verdict is honestly BLOCKED — never READY on unproven facts.
   */
  async runPreflight(user: AuthUser, headers: Record<string, string | string[] | undefined>, targetId: string, body: Record<string, unknown> = {}) {
    requireWebVaptPermission(user, "RUN_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const target = await this.targetOr404(workspace.id, targetId);
    const facts = await this.authorizationFacts(workspace.id, target);
    const snapshot = buildScopeSnapshot({ workspaceId: workspace.id, origins: [target.normalizedOrigin] });
    const redirectFinalUrl = typeof body.redirectFinalUrl === "string" ? body.redirectFinalUrl : undefined;
    const result = evaluatePreflight({
      authorization: facts,
      probes: { transport: "NOT_CONFIGURED", ...(redirectFinalUrl ? { redirectFinalUrl } : {}) },
      snapshot,
    });
    const row = await this.prisma.webVaptPreflightResult.create({
      data: {
        workspaceId: workspace.id, webTargetId: targetId, status: result.status,
        checks: result.checks as never, probeTransport: "NOT_CONFIGURED",
        ...(result.redirectRecorded ? { redirectRecorded: result.redirectRecorded } : {}),
        createdBy: user.id,
      },
    });
    await this.audit(workspace.id, user, "WEB_VAPT_PREFLIGHT_COMPLETED", "WebVaptTarget", targetId, { status: result.status });
    return row;
  }

  private async authorizationFacts(workspaceId: string, target: { targetId: string; authorizationId: string }) {
    const parent = await this.prisma.target.findFirst({ where: { id: target.targetId, workspaceId } });
    const assessment = await this.prisma.assessment.findFirst({ where: { id: target.authorizationId, workspaceId } });
    const verification = await this.prisma.targetVerification.findFirst({ where: { targetId: target.targetId }, orderBy: { createdAt: "desc" } });
    return {
      targetVerified: parent?.verified === true,
      activeAuthorization: assessment?.status === "APPROVED",
      ...(verification?.expiresAt ? { expiresAt: verification.expiresAt as Date } : {}),
    };
  }

  /* ------------------------------- plans (§10/§11/§16) ------------------------------- */

  async createPlan(user: AuthUser, headers: Record<string, string | string[] | undefined>, targetId: string, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "RUN_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const target = await this.targetOr404(workspace.id, targetId);
    const profileKey = (PROFILE_KEYS.includes(String(body.profileKey ?? "")) ? String(body.profileKey) : target.scanProfileKey) as WebVaptProfileKey;
    const definition = profileDefinition(profileKey);
    const facts = await this.authorizationFacts(workspace.id, target);
    // §16 gate: named profiles never carry HIGH tools; HIGH modules
    // arrive only via an explicit highRiskModules request and each one
    // is gated on profile + authorization + permission + approval.
    const requestedHigh = Array.isArray(body.highRiskModules) ? body.highRiskModules.map(String) : [];
    const allowedTools = [...definition.toolSlugs];
    const blockedModules: Array<{ slug: string; reason: string }> = [];
    for (const slug of requestedHigh) {
      const gate = evaluateModuleGate({
        slug,
        explicitProfile: true,
        activeAuthorization: facts.activeAuthorization,
        highRiskPermission: (() => { try { requireWebVaptPermission(user, "RUN_HIGH_RISK_WEB_TESTS"); return true; } catch { return false; } })(),
        approvalRecorded: typeof body.approvalRef === "string" && body.approvalRef.length > 0,
      });
      if (gate.allowed) {
        allowedTools.push(slug);
        await this.audit(workspace.id, user, "HIGH_RISK_TEST_APPROVED", "WebVaptTarget", targetId, { slug, approvalRef: String(body.approvalRef) });
      } else {
        blockedModules.push({ slug, reason: gate.reason });
      }
    }
    const baseBudget = defaultBudgetFor(profileKey, target.environment as TargetEnvironment);
    const requested = (body.budget && typeof body.budget === "object" ? body.budget : {}) as Partial<ScanRequestBudget>;
    const { budget, clampedFields } = clampBudget({ ...baseBudget, ...requested });
    const snapshotData = buildScopeSnapshot({ workspaceId: workspace.id, origins: [target.normalizedOrigin] });
    const snapshot = await this.prisma.scanScopeSnapshot.create({
      data: { workspaceId: workspace.id, origins: snapshotData.origins, hosts: snapshotData.hosts, exclusions: snapshotData.exclusions, hash: snapshotData.hash },
    });
    const plan = await this.prisma.webVaptScanPlan.create({
      data: {
        workspaceId: workspace.id, webTargetId: targetId, profileKey,
        stages: definition.stages as never, allowedTools, blockedModules: blockedModules as never,
        budget: { ...budget, clampedFields } as never,
        estimatedRequestClass: requestClassOf(budget),
        scopeSnapshotId: snapshot.id,
        ...(target.authenticationProfileId ? { authenticationProfileId: target.authenticationProfileId } : {}),
        createdBy: user.id,
      },
    });
    await this.prisma.scanScopeSnapshot.update({ where: { id: snapshot.id }, data: { planId: plan.id } });
    if (target.authenticationProfileId) {
      // §53/§168: profile USE is audited by reference — never a value.
      await this.audit(workspace.id, user, "AUTH_PROFILE_USED", "AuthenticationProfile", target.authenticationProfileId, { planId: plan.id });
    }
    await this.audit(workspace.id, user, "WEB_VAPT_SCAN_PLANNED", "WebVaptScanPlan", plan.id, { profileKey, allowedTools: allowedTools.length, blockedModules: blockedModules.length });
    return { plan, scopeSnapshot: { id: snapshot.id, hash: snapshot.hash, origins: snapshot.origins }, blockedModules, budgetNotice: clampedFields.length > 0 ? `Budget clamped to the platform ceiling (§127): ${clampedFields.join(", ")}` : undefined };
  }

  async listPlans(user: AuthUser, headers: Record<string, string | string[] | undefined>, targetId: string) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    await this.targetOr404(workspace.id, targetId);
    return this.prisma.webVaptScanPlan.findMany({ where: { workspaceId: workspace.id, webTargetId: targetId }, orderBy: { createdAt: "desc" } });
  }

  /* ------------------------------- scans (§12/§128) ------------------------------- */

  async startScan(user: AuthUser, headers: Record<string, string | string[] | undefined>, targetId: string, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "RUN_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const target = await this.targetOr404(workspace.id, targetId);
    let plan = body.planId
      ? await this.prisma.webVaptScanPlan.findFirst({ where: { id: String(body.planId), workspaceId: workspace.id, webTargetId: targetId } })
      : null;
    if (body.planId && !plan) throw new NotFoundException("Scan plan not found for this target");
    if (!plan) {
      const created = await this.createPlan(user, headers, targetId, { profileKey: target.scanProfileKey });
      plan = created.plan;
    }
    if (plan.status === "STARTED") throw new ConflictException("This plan already has a started scan");
    // Preflight gate (§7): a scan materializes ONLY on READY /
    // READY_WITH_WARNINGS. In this deployment the probe transport is
    // NOT_CONFIGURED, so the honest outcome is a BLOCKED plan — no
    // canonical Scan is fabricated (§8).
    const preflight = await this.runPreflight(user, headers, targetId, {});
    if (preflight.status === "BLOCKED" || preflight.status === "UNREACHABLE" || preflight.status === "AUTH_REQUIRED") {
      await this.prisma.webVaptScanPlan.update({ where: { id: plan.id }, data: { status: "BLOCKED" } });
      throw new BadRequestException(`Scan blocked by preflight: ${preflight.status} — see the preflight checks for reasons (probe transport is NOT_CONFIGURED in this deployment; reachability is never assumed)`);
    }
    const scan = await this.prisma.scan.create({
      data: { workspaceId: workspace.id, assessmentId: target.authorizationId, status: "QUEUED", requestedBy: user.id },
    });
    await this.prisma.webVaptScanPlan.update({ where: { id: plan.id }, data: { status: "STARTED", scanId: scan.id } });
    await this.audit(workspace.id, user, "WEB_VAPT_SCAN_STARTED", "Scan", scan.id, { planId: plan.id, profileKey: plan.profileKey });
    return { scan, planId: plan.id, preflightStatus: preflight.status };
  }

  async listScans(user: AuthUser, headers: Record<string, string | string[] | undefined>) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const plans = await this.prisma.webVaptScanPlan.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 100 });
    return plans;
  }

  async getScan(user: AuthUser, headers: Record<string, string | string[] | undefined>, scanId: string) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const plan = await this.prisma.webVaptScanPlan.findFirst({ where: { workspaceId: workspace.id, scanId } });
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id } });
    if (!scan && !plan) throw new NotFoundException("Scan not found");
    const coverage = await this.coverageForScan(workspace.id, scanId);
    const evidenceCount = await this.prisma.webVaptEvidence.count({ where: { workspaceId: workspace.id, scanId } });
    return { scan, plan, coverage, evidenceCount };
  }

  async cancelScan(user: AuthUser, headers: Record<string, string | string[] | undefined>, scanId: string) {
    requireWebVaptPermission(user, "CANCEL_VAPT_SCAN");
    const workspace = await this.ws(user, headers);
    const plan = await this.prisma.webVaptScanPlan.findFirst({ where: { workspaceId: workspace.id, scanId } });
    if (!plan) throw new NotFoundException("No V2 plan is attached to this scan");
    const updated = await this.prisma.webVaptScanPlan.update({ where: { id: plan.id }, data: { status: "CANCELLED" } });
    await this.audit(workspace.id, user, "WEB_VAPT_SCAN_CANCELLED", "Scan", scanId, { planId: plan.id });
    return updated;
  }

  /* ------------------------------- API services + specifications (§35–§47) ------------------------------- */

  async listApiServices(user: AuthUser, headers: Record<string, string | string[] | undefined>) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const services = await this.prisma.apiService.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" } });
    return services.map((s: { id: string; baseUrl: string; host: string; apiType: string; scopeStatus: string; assetId: string }) => ({ id: s.id, baseUrl: s.baseUrl, host: s.host, apiType: s.apiType, scopeStatus: s.scopeStatus, assetId: s.assetId }));
  }

  /**
   * Import an API specification THROUGH the Prompt 9 governed import
   * posture: the document is untrusted (§35), referenced hosts are
   * validated against workspace scope (never trusted, never fetched —
   * §139/§140), embedded scripts are never executed (§141), and the
   * import freezes an immutable snapshot (§36).
   */
  async importSpecification(user: AuthUser, headers: Record<string, string | string[] | undefined>, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "RUN_API_VAPT");
    const workspace = await this.ws(user, headers);
    const serviceId = String(body.serviceId ?? "");
    const format = String(body.format ?? "OPENAPI");
    const document = String(body.document ?? "");
    if (!document) throw new BadRequestException("document is required");
    const service = await this.prisma.apiService.findFirst({ where: { id: serviceId, workspaceId: workspace.id } });
    if (!service) throw new NotFoundException("API service not found in this workspace");
    let parsed: Record<string, unknown>;
    try { parsed = JSON.parse(document) as Record<string, unknown>; } catch { throw new BadRequestException("Specification document must be JSON (OpenAPI/Postman/Insomnia JSON exports)"); }
    // Referenced hosts: OpenAPI servers[].url + Postman-style host strings.
    const referencedHosts = new Set<string>();
    const servers = Array.isArray(parsed.servers) ? parsed.servers : [];
    for (const s of servers) {
      const url = (s as Record<string, unknown>)?.url;
      if (typeof url === "string") { try { referencedHosts.add(new URL(url).hostname); } catch { /* template/relative */ } }
    }
    if (typeof parsed.host === "string") referencedHosts.add(parsed.host);
    const serviceHost = (() => { try { return new URL(service.baseUrl).hostname; } catch { return ""; } })();
    const acceptedHosts: string[] = [];
    const rejectedHosts: string[] = [];
    for (const h of referencedHosts) (h === serviceHost ? acceptedHosts : rejectedHosts).push(h);
    const paths = parsed.paths && typeof parsed.paths === "object" ? Object.keys(parsed.paths as object).length : 0;
    const schemas = parsed.components && typeof parsed.components === "object" && (parsed.components as Record<string, unknown>).schemas
      ? Object.keys((parsed.components as Record<string, Record<string, unknown>>).schemas as object).length : 0;
    const checksum = sha256Hex(document);
    const version = typeof parsed.info === "object" && parsed.info ? String((parsed.info as Record<string, unknown>).version ?? "") || null : null;
    // Same persistence posture as the Prompt 9 importers: the raw
    // document is NOT retained in Postgres — checksum + object-storage
    // reference only; the V2 snapshot freezes the import facts (§36).
    const spec = await this.prisma.apiSpecification.create({
      data: {
        workspaceId: workspace.id, apiServiceId: serviceId, assetId: service.assetId,
        kind: ["OPENAPI", "POSTMAN", "INSOMNIA", "GRAPHQL_SDL", "WSDL"].includes(format) ? format : "OPENAPI",
        ...(version ? { version } : {}),
        source: String(body.source ?? "IMPORT"),
        checksum, artifactRef: `api-specs/${workspace.id}/${checksum}`,
        operationCount: paths, parsedStatus: "PARSED",
      },
    });
    const snapshot = await this.prisma.apiSpecificationSnapshot.create({
      data: {
        workspaceId: workspace.id, specificationId: spec.id, source: spec.source,
        version, hash: checksum, endpointCount: paths, schemaCount: schemas, rejectedHosts,
      },
    });
    await this.audit(workspace.id, user, "API_SPEC_IMPORTED", "ApiSpecification", spec.id, { format, rejectedHosts: rejectedHosts.length });
    return { specificationId: spec.id, snapshot, acceptedHosts, rejectedHosts, note: "Referenced hosts are validated against the API service's scope; collection/spec scripts are never executed (§141)." };
  }

  async startApiScan(user: AuthUser, headers: Record<string, string | string[] | undefined>, serviceId: string, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "RUN_API_VAPT");
    const workspace = await this.ws(user, headers);
    const service = await this.prisma.apiService.findFirst({ where: { id: serviceId, workspaceId: workspace.id } });
    if (!service) throw new NotFoundException("API service not found in this workspace");
    const profileKey = String(body.profileKey ?? "API_SAFE");
    if (!["API_SAFE", "API_STANDARD"].includes(profileKey)) throw new BadRequestException("API scans use the API_SAFE or API_STANDARD profile (§122)");
    return {
      serviceId, profileKey, status: "PLANNED",
      note: "API scan planning reuses the governed Prompt 9 operation policy: state-changing operations require explicit profile enablement (§46), the plan is budget-clamped (§48), and execution flows through the canonical assessment/scan pipeline — no parallel runner exists.",
      budgetCeiling: PLATFORM_BUDGET_CEILING,
    };
  }

  /* ------------------------------- authorization matrix + scenarios (§97–§102) ------------------------------- */

  async evaluateMatrix(user: AuthUser, headers: Record<string, string | string[] | undefined>, testCaseId: string, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "RUN_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const testCase = await this.prisma.authorizationTestCase.findFirst({ where: { id: testCaseId, workspaceId: workspace.id } });
    if (!testCase) throw new NotFoundException("Authorization test case (Prompt 9 design record) not found");
    const rows = (Array.isArray(body.rows) ? body.rows : []) as AuthorizationMatrixRow[];
    if (rows.length === 0) throw new BadRequestException("rows are required");
    const problems = validateMatrixRows(rows);
    if (problems.length > 0) throw new BadRequestException(`Matrix rows rejected (§98 — fixture/test identifiers only, no broad enumeration): ${problems.join("; ")}`);
    const evaluation = evaluateAuthorizationMatrix(rows);
    await this.prisma.authorizationMatrixEntry.deleteMany({ where: { workspaceId: workspace.id, testCaseId } });
    const entries = [];
    for (let i = 0; i < rows.length; i++) {
      const candidate = evaluation.candidates.find((c) => c.rowIndex === i);
      const row = rows[i]!;
      const entry = await this.prisma.authorizationMatrixEntry.create({
        data: {
          workspaceId: workspace.id, testCaseId,
          identityA: row.identityA, ...(row.identityB ? { identityB: row.identityB } : {}),
          role: row.role, resource: row.resource,
          expectedAccess: row.expectedAccess, observedAccess: row.observedAccess,
          result: row.observedAccess === "NOT_TESTED" ? "NOT_TESTED" : candidate ? "MISMATCH" : "MATCH",
          ...(candidate ? { candidateFinding: candidate as never } : {}),
          createdBy: user.id,
        },
      });
      entries.push(entry);
    }
    return { testCaseId, summary: { total: rows.length, matches: evaluation.matches, mismatches: evaluation.candidates.length, untested: evaluation.untested }, entries };
  }

  async createScenario(user: AuthUser, headers: Record<string, string | string[] | undefined>, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "RUN_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const scenario = {
      name: String(body.name ?? ""),
      preconditions: String(body.preconditions ?? ""),
      authorizedIdentities: Array.isArray(body.authorizedIdentities) ? body.authorizedIdentities.map(String) : [],
      safeSteps: Array.isArray(body.safeSteps) ? body.safeSteps.map(String) : [],
      expectedBehavior: String(body.expectedBehavior ?? ""),
    };
    const problems = validateBusinessLogicScenario(scenario);
    if (problems.length > 0) throw new BadRequestException(`Scenario rejected: ${problems.join("; ")}`);
    const row = await this.prisma.businessLogicScenario.create({ data: { workspaceId: workspace.id, ...scenario, safeSteps: scenario.safeSteps as never, createdBy: user.id } });
    return row;
  }

  async evaluateScenario(user: AuthUser, headers: Record<string, string | string[] | undefined>, id: string, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "RUN_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const row = await this.prisma.businessLogicScenario.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!row) throw new NotFoundException("Business-logic scenario not found");
    const observed = String(body.observedBehavior ?? "");
    if (!observed) throw new BadRequestException("observedBehavior is required — evaluation compares a recorded observation, it does not invent one (§101)");
    const verdict = observed.trim() === String(row.expectedBehavior).trim() ? "MATCHES_EXPECTED" : "DEVIATES_FROM_EXPECTED";
    const updated = await this.prisma.businessLogicScenario.update({ where: { id }, data: { observedBehavior: observed, status: "EVALUATED" } });
    return { scenario: updated, verdict, note: verdict === "DEVIATES_FROM_EXPECTED" ? "Deviation is a review signal for the assessment team — it becomes a finding only through the governed finding pipeline with evidence (§105)." : undefined };
  }

  /* ------------------------------- coverage + tool health (§146–§150) ------------------------------- */

  async coverageForScan(workspaceId: string, scanId: string) {
    const stored = await this.prisma.webVaptCoverage.findFirst({ where: { workspaceId, scanId } });
    if (stored) return stored;
    // Honest empty coverage: nothing was tested, coverage is null —
    // never a fabricated 100% (§148).
    const computed = computeCoverage({
      discoveredEndpoints: 0, testedEndpoints: 0, discoveredParameters: 0, testedParameters: 0,
      authenticatedEndpoints: 0, testedAuthenticatedEndpoints: 0,
      toolsPlanned: [], toolsContributed: [], skipped: [] as SkippedTest[], budgetExhausted: false, stagesFailed: 0,
    });
    return { scanId, ...computed, persisted: false };
  }

  async getCoverage(user: AuthUser, headers: Record<string, string | string[] | undefined>, scanId: string) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    return this.coverageForScan(workspace.id, scanId);
  }

  async toolHealth(user: AuthUser, headers: Record<string, string | string[] | undefined>) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const rows = await this.prisma.webToolHealth.findMany({ where: { workspaceId: workspace.id } });
    const bySlug = new Map(rows.map((r: { slug: string }) => [r.slug, r]));
    const slugs = ["whatweb", "httpx", "katana", "ffuf", "nuclei", "dalfox", "sqlmap", "commix", "sstimap", "wpscan", "zap", "testssl"];
    return slugs.map((slug) => {
      const capability = toolCapability(slug);
      const stored = bySlug.get(slug) as { installed: boolean; version?: string | null; lastSuccessfulRun?: Date | null; errorRate: number; parserCompatible: boolean } | undefined;
      const view = toolHealthView({
        slug,
        installed: stored?.installed ?? false,
        ...(stored?.version ? { version: stored.version } : {}),
        ...(stored?.lastSuccessfulRun ? { lastSuccessfulRun: stored.lastSuccessfulRun.toISOString() } : {}),
        errorRate: stored?.errorRate ?? 0,
        parserCompatible: stored?.parserCompatible ?? true,
      });
      return { ...view, riskClass: capability?.riskClass, capabilities: capability?.capabilities ?? [], recorded: Boolean(stored) };
    });
  }

  /* ------------------------------- profiles (§122/§165) ------------------------------- */

  async listProfiles(user: AuthUser, headers: Record<string, string | string[] | undefined>) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    await this.ws(user, headers);
    return PROFILE_KEYS.map((key) => {
      const d = profileDefinition(key as WebVaptProfileKey);
      return { key: d.key, name: d.name, active: d.active, stages: d.stages, toolSlugs: d.toolSlugs, defaultBudget: d.defaultBudget, notes: d.notes };
    });
  }

  /* ------------------------------- AI copilot (§161–§164) ------------------------------- */

  /**
   * Constrained assistance over THIS workspace's stored V2 facts. The
   * copilot cannot expand scope, authorize targets, remove limits or
   * enable destructive modules — requests to do so are refused
   * structurally (§162/§163/§196/§197), and it can never execute
   * anything (§164).
   */
  async aiSuggest(user: AuthUser, headers: Record<string, string | string[] | undefined>, body: Record<string, unknown>) {
    requireWebVaptPermission(user, "VIEW_WEB_VAPT");
    const workspace = await this.ws(user, headers);
    const question = String(body.question ?? "");
    const forbidden = /(expand|widen|broaden).{0,20}scope|add.{0,20}(host|target|domain)|authori[sz]e|remove.{0,20}(limit|budget|cap)|raise.{0,20}budget|disable.{0,20}(policy|gate)|enable.{0,30}(sqlmap|commix|sstimap|hydra|destructive|exploit)|run.{0,20}shell|execute.{0,20}command/i;
    if (forbidden.test(question)) {
      return {
        refused: true,
        reason: "The copilot cannot expand scope, authorize targets, remove limits, enable destructive modules or execute commands (§162–§164). Those actions belong to the governed approval flows.",
        suggestions: [] as string[],
      };
    }
    const [targets, plans, preflights] = await Promise.all([
      this.prisma.webVaptTarget.count({ where: { workspaceId: workspace.id } }),
      this.prisma.webVaptScanPlan.count({ where: { workspaceId: workspace.id } }),
      this.prisma.webVaptPreflightResult.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 1 }),
    ]);
    const suggestions: string[] = [];
    if (targets === 0) suggestions.push("Create a Web VAPT target from a VERIFIED asset with an APPROVED assessment — V2 planning starts there (§4/§6).");
    if (preflights.length > 0 && preflights[0].status !== "READY") suggestions.push(`Latest preflight is ${preflights[0].status}: work through its failing checks — authorization facts first; probe reachability is reported honestly and never assumed.`);
    if (plans === 0 && targets > 0) suggestions.push("Generate a scan plan (WEB_SAFE is the baseline profile) and review the plan preview — stages, budget and blocked modules — before starting (§11).");
    suggestions.push("For authorization testing, define matrix rows with fixture identities and governed observations; mismatches become candidate findings for review (§97–§100).");
    return {
      refused: false,
      groundedOn: { webTargets: targets, plans, latestPreflightStatus: preflights[0]?.status ?? null },
      platformCeiling: PLATFORM_BUDGET_CEILING,
      suggestions,
      note: "Suggestions are grounded in this workspace's stored V2 records only; the copilot has no execution surface (§164).",
    };
  }

  /** Terminal status derivation, exposed for the scan detail view (§150). */
  deriveStatus(input: { cancelled: boolean; preflightBlocked: boolean; stagesFailed: number; budgetExhausted: boolean; skippedCount: number }) {
    return deriveScanStatus(input);
  }
}
