import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  BurpIssueParser, CaidoIssueParser, EnvEndpointResolver, EnvSecretResolver, HarImporter,
  HttpScannerTransport, ImportValidationError, InMemoryScannerInstanceProvider,
  PRODUCT_CAPABILITIES, SLUG_PRODUCTS, ScopeMatcher, ZapIssueParser,
  assertImportSize, correlateFindings, createProxyConnectors, evaluateApproval,
  extractParameterNames, hashScopeSnapshot, parseImportJson, validateEndpointReference,
  type ParsedProxy, type ScannerInstanceRecord, type ScannerProduct,
} from "@dsrclone/security-sdk";
import { scopeRulesSchema, type ScopeRules } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";

/**
 * Scanner administration + import service (Prompt 8 §15–§17, §54–§56,
 * §60–§63). Invariants enforced here, at the trust boundary:
 *  - instances store an opaque endpoint REFERENCE + a credential
 *    REFERENCE NAME — never a URL, never a secret value (§15/§20);
 *  - instances are admin-registered only, and health is probed through
 *    the trusted connector with server-side endpoint resolution (§53);
 *  - imports are size-capped, format-validated (XXE-safe), parsed by the
 *    product parsers and reconciled against the scan's findings by
 *    canonical fingerprint — the same correlation identity the worker's
 *    pipeline uses (§32/§33);
 *  - approvals are bound to a scope snapshot hash: any later scope change
 *    invalidates them at gate time (§41–§43).
 */

type InstanceRow = {
  id: string; organizationId: string; workspaceId: string | null; toolId: string;
  name: string; endpointReference: string; deploymentType: string; credentialReference: string | null;
  declaredCapabilities: unknown; detectedCapabilities: unknown; healthStatus: string;
  version: string | null; licenseState: string | null; lastHealthCheckAt: Date | null;
  lastHealthDetail: string | null; enabled: boolean; createdBy: string;
  createdAt: Date; updatedAt: Date; tool?: { slug: string };
};

const PRODUCT_BY_SLUG: Record<string, ScannerProduct> = SLUG_PRODUCTS;

export function toInstanceRecord(row: InstanceRow, toolSlug: string): ScannerInstanceRecord {
  return {
    id: row.id,
    organizationId: row.organizationId,
    ...(row.workspaceId ? { workspaceId: row.workspaceId } : {}),
    toolSlug,
    product: PRODUCT_BY_SLUG[toolSlug] ?? "ZAP",
    name: row.name,
    endpointReference: row.endpointReference,
    deploymentType: row.deploymentType as ScannerInstanceRecord["deploymentType"],
    ...(row.credentialReference ? { credentialReference: row.credentialReference } : {}),
    declaredCapabilities: (Array.isArray(row.declaredCapabilities) ? row.declaredCapabilities : []) as ScannerInstanceRecord["declaredCapabilities"],
    detectedCapabilities: (Array.isArray(row.detectedCapabilities) ? row.detectedCapabilities : []) as ScannerInstanceRecord["detectedCapabilities"],
    healthStatus: row.healthStatus as ScannerInstanceRecord["healthStatus"],
    ...(row.version ? { version: row.version } : {}),
    ...(row.licenseState ? { licenseState: row.licenseState } : {}),
    enabled: row.enabled,
    createdBy: row.createdBy,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** API view of an instance: metadata + reference NAMES only. There is no
 *  field anywhere in this shape that could carry a secret value. */
export function instanceView(row: InstanceRow, toolSlug: string) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    workspaceId: row.workspaceId,
    toolSlug,
    product: PRODUCT_BY_SLUG[toolSlug] ?? null,
    name: row.name,
    endpointReference: row.endpointReference,
    deploymentType: row.deploymentType,
    credentialReference: row.credentialReference,
    declaredCapabilities: row.declaredCapabilities,
    detectedCapabilities: row.detectedCapabilities,
    healthStatus: row.healthStatus,
    version: row.version,
    licenseState: row.licenseState,
    lastHealthCheckAt: row.lastHealthCheckAt,
    lastHealthDetail: row.lastHealthDetail,
    enabled: row.enabled,
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

@Injectable()
export class ScannersService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  // ------------------------------ instances ------------------------------

  private async toolBySlug(slug: string) {
    const tool = await this.prisma.tool.findUnique({ where: { slug } });
    if (!tool) throw new NotFoundException(`Tool ${slug} is not in the catalog`);
    return tool;
  }

  private async findInstance(user: RequestUser, id: string): Promise<InstanceRow> {
    const row = await this.prisma.scannerInstance.findFirst({
      where: { id, organizationId: user.organizationId },
      include: { tool: { select: { slug: true } } },
    });
    if (!row) throw new NotFoundException("Scanner instance not found");
    return row as unknown as InstanceRow;
  }

  async listInstances(user: RequestUser) {
    const rows = await this.prisma.scannerInstance.findMany({
      where: { organizationId: user.organizationId },
      include: { tool: { select: { slug: true } } },
      orderBy: { createdAt: "desc" },
    });
    return (rows as unknown as InstanceRow[]).map((r) => instanceView(r, r.tool?.slug ?? ""));
  }

  async createInstance(user: RequestUser, data: {
    name: string; toolSlug: string; endpointReference: string;
    deploymentType: string; credentialReference?: string;
    declaredCapabilities?: string[]; workspaceId?: string;
  }) {
    const check = validateEndpointReference(data.endpointReference);
    if (!check.ok) {
      throw new BadRequestException(`endpointReference rejected: ${check.reason} — scanner endpoints are opaque references resolved from server configuration, never URLs supplied by clients (§17)`);
    }
    const product = PRODUCT_BY_SLUG[data.toolSlug];
    if (!product) throw new BadRequestException(`toolSlug ${data.toolSlug} is not a proxy scanner product`);
    const ceiling = PRODUCT_CAPABILITIES[product] as string[];
    const declared = data.declaredCapabilities ?? [...ceiling];
    const beyond = declared.filter((c) => !ceiling.includes(c));
    if (beyond.length > 0) {
      throw new BadRequestException(`declaredCapabilities exceed what ${product} can offer: ${beyond.join(", ")} (§14)`);
    }
    const tool = await this.toolBySlug(data.toolSlug);
    let workspaceId: string | null = null;
    if (data.workspaceId) {
      const ws = await resolveWorkspace(this.prisma, user, data.workspaceId);
      workspaceId = ws.id;
    }
    const row = await this.prisma.scannerInstance.create({
      data: {
        organizationId: user.organizationId, workspaceId, toolId: tool.id,
        name: data.name, endpointReference: data.endpointReference,
        deploymentType: data.deploymentType as never,
        credentialReference: data.credentialReference ?? null,
        declaredCapabilities: declared as never,
        detectedCapabilities: [] as never,
        createdBy: user.id,
      },
      include: { tool: { select: { slug: true } } },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspaceId ?? undefined,
      action: "SCANNER_INSTANCE_REGISTERED", resourceType: "ScannerInstance", resourceId: row.id,
      metadata: { toolSlug: data.toolSlug, deploymentType: data.deploymentType, endpointReference: data.endpointReference },
    });
    const r = row as unknown as InstanceRow;
    return instanceView(r, r.tool?.slug ?? data.toolSlug);
  }

  async updateInstance(user: RequestUser, id: string, data: {
    name?: string; enabled?: boolean; credentialReference?: string | null; declaredCapabilities?: string[];
  }) {
    const existing = await this.findInstance(user, id);
    if (data.declaredCapabilities) {
      const product = PRODUCT_BY_SLUG[existing.tool?.slug ?? ""] ?? "ZAP";
      const ceiling = PRODUCT_CAPABILITIES[product] as string[];
      const beyond = data.declaredCapabilities.filter((c) => !ceiling.includes(c));
      if (beyond.length > 0) throw new BadRequestException(`declaredCapabilities exceed what ${product} can offer: ${beyond.join(", ")} (§14)`);
    }
    const row = await this.prisma.scannerInstance.update({
      where: { id },
      data: {
        ...(data.name !== undefined ? { name: data.name } : {}),
        ...(data.enabled !== undefined ? { enabled: data.enabled } : {}),
        ...(data.credentialReference !== undefined ? { credentialReference: data.credentialReference } : {}),
        ...(data.declaredCapabilities !== undefined ? { declaredCapabilities: data.declaredCapabilities as never } : {}),
      },
      include: { tool: { select: { slug: true } } },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: existing.workspaceId ?? undefined,
      action: "SCANNER_INSTANCE_UPDATED", resourceType: "ScannerInstance", resourceId: id,
      metadata: { fields: Object.keys(data) },
    });
    const r = row as unknown as InstanceRow;
    return instanceView(r, r.tool?.slug ?? "");
  }

  async deleteInstance(user: RequestUser, id: string) {
    const existing = await this.findInstance(user, id);
    await this.prisma.scannerInstance.delete({ where: { id } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: existing.workspaceId ?? undefined,
      action: "SCANNER_INSTANCE_UPDATED", resourceType: "ScannerInstance", resourceId: id,
      metadata: { deleted: true },
    });
    return { deleted: true };
  }

  /** Health probe (§53): runs the product connector against THIS
   *  instance only, with the endpoint resolved from server configuration
   *  and the credential resolved by reference. The probe result —
   *  including NOT_CONFIGURED/MISCONFIGURED honesty — is persisted on the
   *  instance row so plan-time health and the admin GUI agree. */
  async healthCheckInstance(user: RequestUser, id: string) {
    const row = await this.findInstance(user, id);
    const toolSlug = row.tool?.slug ?? "";
    const record = toInstanceRecord(row, toolSlug);
    const connectors = createProxyConnectors({
      instances: new InMemoryScannerInstanceProvider([record]),
      endpoints: new EnvEndpointResolver(),
      secrets: new EnvSecretResolver(),
      transport: new HttpScannerTransport(),
    });
    const connector = record.product === "ZAP" ? connectors.zap
      : record.product === "BURP" ? connectors.burp
      : record.product === "MITMPROXY" ? connectors.mitmproxy
      : connectors.caido;
    const health = await connector.healthCheck(record.id);
    const updated = await this.prisma.scannerInstance.update({
      where: { id },
      data: {
        healthStatus: health.status as never,
        version: health.version ?? null,
        licenseState: health.licenseState ?? null,
        detectedCapabilities: connector.detectedCapabilities(record) as never,
        lastHealthCheckAt: new Date(),
        lastHealthDetail: health.detail ?? null,
      },
      include: { tool: { select: { slug: true } } },
    });
    const r = updated as unknown as InstanceRow;
    return { ...instanceView(r, r.tool?.slug ?? toolSlug), latencyMs: health.latencyMs ?? null };
  }

  // ------------------------------ approvals ------------------------------

  async grantApproval(user: RequestUser, data: {
    assessmentId: string; scanId?: string; scannerInstanceId?: string;
    capability: string; expiresAt?: string;
  }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const assessment = await this.prisma.assessment.findFirst({
      where: { id: data.assessmentId, workspaceId: workspace.id },
      include: { target: true, scope: true },
    });
    if (!assessment) throw new NotFoundException("Assessment not found");
    // §40/§70: an approval is meaningless — and dangerous — without the
    // gates it attests to. Granting fails loudly when they do not hold.
    if (!assessment.target.verified) throw new BadRequestException("Active-scan approval requires a VERIFIED target (§40)");
    if (assessment.status !== "APPROVED") throw new BadRequestException("Active-scan approval requires an APPROVED assessment (§40)");
    if (data.scanId) {
      const scan = await this.prisma.scan.findFirst({ where: { id: data.scanId, workspaceId: workspace.id, assessmentId: assessment.id } });
      if (!scan) throw new NotFoundException("Scan not found for this assessment");
    }
    if (data.scannerInstanceId) await this.findInstance(user, data.scannerInstanceId);
    const scopeParse = scopeRulesSchema.safeParse(assessment.scope?.rules ?? {});
    const rules: ScopeRules = scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] };
    const expiresAt = data.expiresAt ? new Date(data.expiresAt) : new Date(Date.now() + 24 * 3600 * 1000);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
      throw new BadRequestException("expiresAt must be a future timestamp (§42)");
    }
    const row = await this.prisma.scanApproval.create({
      data: {
        workspaceId: workspace.id, assessmentId: assessment.id,
        scanId: data.scanId ?? null, scannerInstanceId: data.scannerInstanceId ?? null,
        capability: data.capability, scopeId: assessment.scopeId ?? null,
        scopeSnapshot: rules as never, scopeSnapshotHash: hashScopeSnapshot(rules),
        policySnapshot: { profile: assessment.profile } as never,
        status: "ACTIVE", approvedBy: user.id, expiresAt,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "ACTIVE_SCAN_APPROVAL_GRANTED", resourceType: "ScanApproval", resourceId: row.id,
      metadata: { assessmentId: assessment.id, capability: data.capability, expiresAt: expiresAt.toISOString() },
    });
    return row;
  }

  async listApprovals(user: RequestUser, assessmentId?: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.scanApproval.findMany({
      where: { workspaceId: workspace.id, ...(assessmentId ? { assessmentId } : {}) },
      orderBy: { createdAt: "desc" },
    });
    const now = new Date();
    return rows.map((r) => ({
      ...r,
      evaluatedState: r.status !== "ACTIVE" ? r.status
        : r.expiresAt.getTime() <= now.getTime() ? "EXPIRED" : "ACTIVE",
    }));
  }

  async revokeApproval(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const row = await this.prisma.scanApproval.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!row) throw new NotFoundException("Approval not found");
    if (row.status !== "ACTIVE") return row;
    const updated = await this.prisma.scanApproval.update({
      where: { id },
      data: { status: "REVOKED", revokedBy: user.id, revokedAt: new Date() },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "ACTIVE_SCAN_APPROVAL_REVOKED", resourceType: "ScanApproval", resourceId: id,
      metadata: { assessmentId: row.assessmentId, capability: row.capability },
    });
    return updated;
  }

  /** Gate-time evaluation for a stored approval against the CURRENT
   *  scope (§43) — exposed for the orchestration layer and tests. */
  async evaluateStoredApproval(approvalId: string) {
    const row = await this.prisma.scanApproval.findUnique({ where: { id: approvalId } });
    if (!row) throw new NotFoundException("Approval not found");
    const assessment = await this.prisma.assessment.findFirst({ where: { id: row.assessmentId }, include: { scope: true } });
    const scopeParse = scopeRulesSchema.safeParse(assessment?.scope?.rules ?? {});
    const rules: ScopeRules = scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] };
    return evaluateApproval(
      {
        id: row.id, workspaceId: row.workspaceId, assessmentId: row.assessmentId,
        ...(row.scanId ? { scanId: row.scanId } : {}), capability: row.capability,
        ...(row.scannerInstanceId ? { scannerInstanceId: row.scannerInstanceId } : {}),
        approvedBy: row.approvedBy, approvedAt: row.approvedAt.toISOString(),
        expiresAt: row.expiresAt.toISOString(), scopeSnapshotHash: row.scopeSnapshotHash,
        ...(row.scopeId ? { scopeId: row.scopeId } : {}), status: row.status as never,
        ...(row.revokedAt ? { revokedAt: row.revokedAt.toISOString() } : {}),
      },
      { capability: "ACTIVE_WEB_SCANNING", currentScopeHash: hashScopeSnapshot(rules) },
    );
  }

  // ------------------------------ imports ------------------------------

  /** Manual scanner-export import (§32/§61–§63): strict size/format
   *  guards first, product parser second, canonical-fingerprint
   *  reconciliation against the scan's existing findings third. Imported
   *  findings are REAL source data only — nothing is synthesized. */
  async importExport(user: RequestUser, data: { format: string; payload: string; scanId: string }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({
      where: { id: data.scanId, workspaceId: workspace.id },
      include: { assessment: { include: { target: true, scope: true } } },
    });
    if (!scan) throw new NotFoundException("Scan not found");
    let parsed: ParsedProxy;
    try {
      assertImportSize(data.payload);
      if (data.format === "zap-json") parsed = new ZapIssueParser().parse(parseImportJson(data.payload));
      else if (data.format === "burp-xml") parsed = new BurpIssueParser().parse(data.payload);
      else if (data.format === "caido-json") parsed = new CaidoIssueParser().parse(parseImportJson(data.payload));
      else if (data.format === "har") parsed = new HarImporter().parse(parseImportJson(data.payload));
      else throw new BadRequestException(`Unsupported import format ${data.format}`);
    } catch (err) {
      if (err instanceof ImportValidationError) throw new BadRequestException(err.message);
      if (err instanceof BadRequestException) throw err;
      throw new BadRequestException(`Import payload could not be parsed: ${err instanceof Error ? err.message : "invalid payload"}`);
    }

    const scopeParse = scopeRulesSchema.safeParse(scan.assessment.scope?.rules ?? {});
    const rules: ScopeRules = scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] };
    const matcher = new ScopeMatcher(rules);
    const targetId = scan.assessment.targetId;

    // Endpoints + assets (asset = the target's host record, §30/§31).
    let endpoints = 0;
    const assetIdByHost = new Map<string, string>();
    const ensureAsset = async (host: string): Promise<string | undefined> => {
      if (assetIdByHost.has(host)) return assetIdByHost.get(host);
      const verdict = matcher.isDiscoveredAssetInScope(host);
      const existing = await this.prisma.asset.findFirst({ where: { targetId, host } });
      const row = existing ?? await this.prisma.asset.create({
        data: {
          workspaceId: workspace.id, targetId, host, type: "HOST",
          scopeStatus: verdict.allowed ? "IN_SCOPE" : "OUT_OF_SCOPE",
          sources: ["import"], discoveredByScanId: scan.id,
        },
      });
      assetIdByHost.set(host, row.id);
      return row.id;
    };
    for (const ep of parsed.endpoints) {
      let host: string;
      try { host = new URL(ep.url).hostname; } catch { continue; }
      const assetId = await ensureAsset(host);
      if (!assetId) continue;
      const existingEp = await this.prisma.endpoint.findFirst({ where: { assetId, url: ep.url } });
      if (existingEp) {
        await this.prisma.endpoint.update({
          where: { id: existingEp.id },
          data: { sources: [...new Set([...existingEp.sources, ...(ep.sources ?? [ep.source ?? "import"])])].sort() },
        });
      } else {
        await this.prisma.endpoint.create({
          data: {
            assetId, url: ep.url, method: ep.method ?? "GET", statusCode: ep.statusCode,
            parameterNames: ep.parameterNames ?? extractParameterNames(ep.url),
            source: ep.source, scopeStatus: matcher.isUrlAllowed(ep.url) ? "IN_SCOPE" : "OUT_OF_SCOPE",
            endpointType: "UNKNOWN", sources: ep.sources ?? [ep.source ?? "import"],
          },
        });
      }
      endpoints++;
    }

    // Transactions (§25): metadata + hashes + redacted copies only.
    let transactions = 0;
    for (const tx of parsed.transactions) {
      await this.prisma.httpTransaction.create({
        data: {
          scanId: scan.id, workspaceId: workspace.id,
          assetId: await ensureAsset(tx.host),
          method: tx.method, url: tx.url, host: tx.host, statusCode: tx.statusCode,
          source: tx.source, scopeStatus: matcher.isUrlAllowed(tx.url) ? "IN_SCOPE" : "OUT_OF_SCOPE",
          requestHash: tx.requestHash, responseHash: tx.responseHash,
          requestSize: tx.requestSize, responseSize: tx.responseSize,
          requestRedacted: tx.requestRedacted, responseRedacted: tx.responseRedacted,
          ...(tx.timestamp ? { observedAt: new Date(tx.timestamp) } : {}),
        },
      });
      transactions++;
    }
    for (const ws of parsed.webSockets) {
      let host: string;
      try { host = new URL(ws.url).hostname; } catch { continue; }
      await ensureAsset(host);
      await this.prisma.webSocketEndpoint.upsert({
        where: { scanId_url: { scanId: scan.id, url: ws.url } },
        create: { scanId: scan.id, workspaceId: workspace.id, url: ws.url, origin: ws.origin, subprotocol: ws.subprotocol, source: ws.source, scopeStatus: matcher.isUrlAllowed(ws.url) ? "IN_SCOPE" : "OUT_OF_SCOPE" },
        update: { source: ws.source },
      });
    }

    // Findings: correlate the batch, then merge-or-create by canonical
    // fingerprint (§33) — the same identity the worker pipeline uses.
    let created = 0;
    let merged = 0;
    const { findings: canonical } = correlateFindings(parsed.findings, { maxFindings: 1000 });
    for (const c of canonical) {
      const evidenceCreates = c.sources.map((s) => ({
        sourceTool: s.tool, evidenceType: "TEXT", summary: s.summary,
        fingerprint: s.sourceFingerprint, matchedAt: s.evidence?.matchedAt,
        metadata: (s.evidence ? {
          ...(s.evidence.checkId ? { checkId: s.evidence.checkId } : {}),
          ...(s.evidence.request ? { request: s.evidence.request } : {}),
          ...(s.evidence.response ? { response: s.evidence.response } : {}),
          ...(s.evidence.metadata ?? {}),
        } : undefined) as never,
      }));
      const existing = await this.prisma.finding.findFirst({ where: { scanId: scan.id, fingerprint: c.canonicalFingerprint } });
      if (existing) {
        for (const e of evidenceCreates) {
          await this.prisma.findingEvidence.create({ data: { findingId: existing.id, ...e } });
        }
        await this.prisma.finding.update({
          where: { id: existing.id },
          data: { sources: [...new Set([...existing.sources, ...c.sources.map((s) => s.tool)])].sort() },
        });
        await this.prisma.findingHistory.create({
          data: { findingId: existing.id, workspaceId: workspace.id, event: "CORRELATED", metadata: { importFormat: data.format, sources: c.sources.map((s) => s.tool) } as never },
        });
        merged++;
        continue;
      }
      await this.prisma.finding.create({
        data: {
          workspaceId: workspace.id, scanId: scan.id,
          assetId: c.finding.host ? await ensureAsset(c.finding.host) : undefined,
          title: c.finding.title, description: c.finding.description,
          severity: c.finding.severity as never, confidence: c.confidenceScore,
          confidenceBand: c.confidenceBand, verificationStatus: c.verificationStatus as never,
          riskScore: c.riskScore, riskBand: c.riskBand, riskExplanation: c.riskExplanation as never,
          host: c.finding.host, endpoint: c.finding.endpoint, parameter: c.finding.parameter,
          fingerprint: c.canonicalFingerprint, isMock: false, status: "OPEN",
          vulnClass: c.finding.vulnClass, sources: c.sources.map((s) => s.tool),
          cve: c.finding.cve, cwe: c.finding.cwe, owaspCategory: c.finding.owaspCategory,
          cvssScore: c.finding.cvssScore, cvssVector: c.finding.cvssVector,
          port: c.finding.port, protocol: c.finding.protocol,
          technicalImpact: c.finding.technicalImpact, businessImpact: c.finding.businessImpact,
          remediation: c.finding.remediation,
          evidence: { create: evidenceCreates },
          references: { create: c.finding.referencesDetailed.map((r) => ({ type: r.type, label: r.label, url: r.url })) },
          history: { create: { workspaceId: workspace.id, event: "CREATED", metadata: { importFormat: data.format } as never } },
        },
      });
      created++;
    }

    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SCANNER_IMPORT_COMPLETED", resourceType: "Scan", resourceId: scan.id,
      metadata: { format: data.format, findingsCreated: created, findingsMerged: merged, endpoints, transactions },
    });
    return {
      format: data.format,
      findings: { created, merged, total: canonical.length },
      endpoints, transactions,
      webSockets: parsed.webSockets.length,
      observations: parsed.observations.length,
      warnings: parsed.warnings,
    };
  }
}
