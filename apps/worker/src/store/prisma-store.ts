import { prisma } from "@dsrclone/database";
import { scopeRulesSchema } from "@dsrclone/validation";
import { idempotencyKey, type ScanEventRecord, type ScanPlan } from "@dsrclone/orchestration";
import {
  CidrPolicyService, EnvSecretResolver, JwtToolAdapter, PROXY_SLUGS, clampDiscoveryBudget, computeRisk, expandCidrTargets,
} from "@dsrclone/security-sdk";
import type { ExecutionContextRecord } from "../executors/stage-executor";
import type { ScanRunRecord, ScanRunStore } from "../consumers/dag-runner";
import { correlateProcessedFindings, type ProcessedFinding, type ProcessedResult } from "../executors/result-processor";

/**
 * Prisma implementation of the worker stores. Workers load ALL trusted state
 * from the database (Prompt 4 §14) — queue payloads carry IDs only, so
 * nothing in Redis is ever trusted for authorization, scope or tenancy.
 */

function hostOf(value: string): string {
  try {
    if (value.includes("://")) return new URL(value).hostname;
  } catch { /* fall through */ }
  return value.split("/")[0]!.split(":")[0]!.toLowerCase();
}

async function loadScanGraph(scanId: string) {
  // Scan has no direct workspace relation — tenancy resolves via workspaceId.
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      plan: true,
      assessment: { include: { target: true, scope: true } },
    },
  });
  if (!scan) return null;
  const workspace = await prisma.workspace.findUnique({ where: { id: scan.workspaceId } });
  if (!workspace) return null;
  return { ...scan, workspace };
}

export class PrismaWorkerStore implements ScanRunStore {
  // ---------- ExecutionStore ----------
  async loadExecutionContext(executionId: string): Promise<ExecutionContextRecord | null> {
    const exec = await prisma.toolExecution.findUnique({
      where: { id: executionId },
      include: { scanStage: true, tool: true },
    });
    if (!exec) return null;
    const graph = await loadScanGraph(exec.scanId);
    if (!graph?.plan || !graph.assessment) return null;
    const plan = graph.plan.plan as unknown as ScanPlan;
    const stageType = exec.scanStage?.type ?? "";
    const planned = plan.stages.find((s) => s.type === stageType);
    const scopeParse = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
    const target = graph.assessment.target;
    return {
      executionId: exec.id,
      scanId: exec.scanId,
      stageId: stageType,
      workspaceId: graph.workspaceId,
      organizationId: graph.workspace.organizationId,
      adapterSlug: exec.tool.slug,
      status: exec.status,
      attempt: exec.attempt,
      timeoutSeconds: planned?.timeoutSeconds ?? 300,
      targetType: target.type,
      targetValue: target.value,
      targetHost: hostOf(target.value),
      scopeRules: scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
      auth: {
        organizationId: graph.workspace.organizationId,
        workspaceId: graph.workspaceId,
        targetId: target.id,
        targetOrganizationId: graph.workspace.organizationId,
        assessmentId: graph.assessmentId,
        scanId: exec.scanId,
        verificationStatus: target.verified ? "VERIFIED" : "PENDING",
        approvalStatus: graph.assessment.status === "APPROVED" ? "APPROVED" : "PENDING",
        requestedBy: graph.requestedBy,
      },
      targetExists: true,
      targetWorkspaceId: graph.workspaceId,
      targetVerified: target.verified,
      assessmentApproved: graph.assessment.status === "APPROVED",
      scopeValid: scopeParse.success,
      networkCapable: planned?.networkCapable ?? false,
      profile: plan.profile,
      assessmentId: graph.assessmentId,
      // Prompt 10 §19/§20: no administrator-approval record source exists
      // in this phase's data model, so Masscan stays denied by default —
      // the honest state. The approval record lands with the admin
      // policy surface; until then the executor gate refuses Masscan.
      masscanApproved: false,
      // Prompt 10 §45: the newest authorized capture for this scan is
      // what tshark may analyze — resolved from trusted rows only.
      captureRef: await this.loadCaptureRef(exec.scanId),
      scanner: await this.loadScannerBinding(exec.tool.slug, graph.workspaceId, graph.workspace.organizationId),
      stageInputs: await this.loadStageInputs(target.id),
      simulation: {
        fixture: (plan.profile === "PASSIVE_RECON" || plan.profile === "WEB_BASELINE") && stageType === "PASSIVE_RECON",
      },
    };
  }

  /** Prompt 10 §45: latest packet-capture artifact reference for a scan. */
  private async loadCaptureRef(scanId: string): Promise<string | undefined> {
    const capture = await prisma.packetCaptureArtifact.findFirst({
      where: { scanId },
      orderBy: { createdAt: "desc" },
      select: { storageKey: true },
    });
    return capture?.storageKey;
  }

  /** Prompt 8 scanner binding (§16): the workspace's admin-registered
   *  instance for this connector — workspace-specific rows win over
   *  org-wide ones. Resolved from trusted DB state only; the queue
   *  payload and the client never name an instance or an endpoint. */
  private async loadScannerBinding(toolSlug: string, workspaceId: string, organizationId: string): Promise<{ instanceId?: string } | undefined> {
    if (!(PROXY_SLUGS as readonly string[]).includes(toolSlug)) return undefined;
    const own = await prisma.scannerInstance.findFirst({
      where: { workspaceId, enabled: true, tool: { slug: toolSlug } },
      orderBy: { createdAt: "asc" },
    });
    if (own) return { instanceId: own.id };
    const orgWide = await prisma.scannerInstance.findFirst({
      where: { workspaceId: null, organizationId, enabled: true, tool: { slug: toolSlug } },
      orderBy: { createdAt: "asc" },
    });
    return orgWide ? { instanceId: orgWide.id } : {};
  }

  /** Discovery inputs for downstream stages (Prompt 5 §26): the target's
   *  in-scope asset hostnames and endpoint URLs discovered so far. Capped so
   *  a huge inventory can't blow up an adapter invocation; out-of-scope
   *  assets are NEVER handed to downstream tools. */
  private async loadStageInputs(targetId: string): Promise<{ hosts: string[]; urls: string[]; technologies: string[]; services: string[]; specUrls: string[]; operations: string[] }> {
    const assets = await prisma.asset.findMany({
      where: { targetId, scopeStatus: "IN_SCOPE" },
      select: { id: true, host: true },
      take: 2000,
      orderBy: { firstSeen: "asc" },
    });
    const endpoints = assets.length === 0 ? [] : await prisma.endpoint.findMany({
      where: { assetId: { in: assets.map((a) => a.id) }, scopeStatus: "IN_SCOPE" },
      select: { url: true },
      take: 2000,
      orderBy: { createdAt: "asc" },
    });
    // Technology names detected so far (Prompt 6 §13 hints for
    // technology-aware wordlist selection).
    const technologies = assets.length === 0 ? [] : await prisma.technology.findMany({
      where: { assetId: { in: assets.map((a) => a.id) } },
      select: { name: true },
      distinct: ["name"],
      take: 200,
    });
    // TLS services for the Prompt 7 TLS stage (§13): only services that
    // look like TLS endpoints (https scheme/name or TLS ports) on in-scope
    // assets — host:port pairs, capped like the rest of the inputs.
    const tlsServices = assets.length === 0 ? [] : await prisma.service.findMany({
      where: {
        assetId: { in: assets.map((a) => a.id) },
        OR: [{ name: { in: ["https", "ssl", "tls"] } }, { port: { in: [443, 8443] } }],
      },
      include: { asset: { select: { host: true } } },
      take: 200,
    });
    const services = [...new Set(tlsServices.map((s) => `${s.asset.host}:${s.port}`))];
    // Prompt 9 (§15): specification locations + imported operations for
    // the schema-testing stage, from the guarded import records of THIS
    // target. Locations are the discovered document URLs; content
    // imports contribute their object-storage reference. Operations are
    // encoded "METHOD path operationId?" for the adapter's policy
    // filter — derived from persisted endpoint inventory only.
    const specifications = await prisma.apiSpecification.findMany({
      where: { targetId, kind: { in: ["OPENAPI", "SWAGGER"] }, parsedStatus: "PARSED" },
      select: { location: true, artifactRef: true },
      take: 20,
      orderBy: { createdAt: "asc" },
    });
    const specUrls = specifications.map((s) => s.location ?? s.artifactRef).filter((v): v is string => !!v);
    const operationRows = assets.length === 0 ? [] : await prisma.endpoint.findMany({
      where: { assetId: { in: assets.map((a) => a.id) }, scopeStatus: "IN_SCOPE" },
      select: { url: true, method: true, path: true, operationId: true },
      take: 2000,
      orderBy: { createdAt: "asc" },
    });
    const operations = operationRows.map((e) => {
      let path = e.path ?? undefined;
      if (!path) { try { path = new URL(e.url).pathname; } catch { path = e.url; } }
      return `${e.method} ${path}${e.operationId ? ` ${e.operationId}` : ""}`;
    });
    return { hosts: assets.map((a) => a.host), urls: endpoints.map((e) => e.url), technologies: technologies.map((t) => t.name), services, specUrls, operations };
  }

  async updateExecution(id: string, patch: Record<string, unknown>): Promise<void> {
    await prisma.toolExecution.update({ where: { id }, data: patch as never });
  }

  async recordEvent(event: ScanEventRecord): Promise<void> {
    await prisma.scanEvent.create({
      data: { scanId: event.scanId, workspaceId: event.workspaceId, type: event.type, payload: event.payload as never },
    });
  }

  async persistResult(scanId: string, executionId: string, processed: ProcessedResult): Promise<{ assets: number; findings: number; endpoints: number; services: number; technologies: number; parameters: number; forms: number; transactions: number; webSockets: number; apiServices: number; graphqlServices: number; jwtProfiles: number; packetCaptures: number }> {
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { assessment: true } });
    if (!scan) return { assets: 0, findings: 0, endpoints: 0, services: 0, technologies: 0, parameters: 0, forms: 0, transactions: 0, webSockets: 0, apiServices: 0, graphqlServices: 0, jwtProfiles: 0, packetCaptures: 0 };
    const assetIdByHost = new Map<string, string>();
    for (const asset of processed.assets) {
      const existing = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host: asset.host } });
      const row = existing
        ? await prisma.asset.update({
            where: { id: existing.id },
            data: {
              scopeStatus: asset.scopeStatus, ip: asset.ip ?? existing.ip, lastSeen: new Date(),
              // Provenance unions across tools/scans (§18); first discoverer
              // scan is kept for the asset's scan history (§44).
              sources: [...new Set([...existing.sources, ...asset.sources])],
              httpStatus: asset.httpStatus ?? existing.httpStatus,
              discoveredByScanId: existing.discoveredByScanId ?? scanId,
              // Prompt 10 §35: OS hints gap-fill only — a later, weaker
              // guess never overwrites a recorded hint.
              osHint: existing.osHint ?? asset.osHint,
              osConfidence: existing.osConfidence ?? asset.osConfidence,
              network: existing.network ?? asset.network,
            },
          })
        : await prisma.asset.create({
            data: {
              workspaceId: scan.workspaceId, targetId: scan.assessment.targetId, host: asset.host,
              ip: asset.ip, type: asset.type, scopeStatus: asset.scopeStatus,
              sources: asset.sources, httpStatus: asset.httpStatus, discoveredByScanId: scanId,
              osHint: asset.osHint, osConfidence: asset.osConfidence, network: asset.network,
            },
          });
      assetIdByHost.set(asset.host, row.id);
    }
    // Services attach to their host's asset (Prompt 5 §32) — upserted on the
    // (assetId, port, protocol) unique key so re-runs refresh metadata.
    // Prompt 10 §49: the update path applies PortResultAggregator
    // semantics — provenance unions, descriptive fields gap-fill from
    // the richer reporter, OPEN outranks CLOSED, confidence takes the
    // max. One canonical row per (asset, port, protocol), always (§31).
    const STATE_RANK: Record<string, number> = { OPEN: 4, OPEN_FILTERED: 3, UNKNOWN: 2, FILTERED: 1, CLOSED: 0 };
    let services = 0;
    for (const svc of processed.services) {
      const assetId = assetIdByHost.get(svc.host);
      if (!assetId) continue;
      const existingSvc = await prisma.service.findUnique({
        where: { assetId_port_protocol: { assetId, port: svc.port, protocol: svc.protocol } },
      });
      if (!existingSvc) {
        await prisma.service.create({
          data: {
            assetId, port: svc.port, protocol: svc.protocol, name: svc.name, product: svc.product, version: svc.version,
            state: svc.state ?? "OPEN", cpe: svc.cpe, banner: svc.banner, tls: svc.tls, confidence: svc.confidence,
            sources: svc.sources ?? [],
          },
        });
      } else {
        await prisma.service.update({
          where: { id: existingSvc.id },
          data: {
            name: (!existingSvc.name || existingSvc.name === "unknown") && svc.name ? svc.name : existingSvc.name,
            product: existingSvc.product ?? svc.product,
            version: existingSvc.version ?? svc.version,
            cpe: existingSvc.cpe ?? svc.cpe,
            banner: existingSvc.banner ?? svc.banner,
            tls: existingSvc.tls ?? svc.tls,
            confidence: Math.max(existingSvc.confidence ?? 0, svc.confidence ?? 0) || existingSvc.confidence,
            state: (STATE_RANK[svc.state ?? "UNKNOWN"] ?? 0) > (STATE_RANK[existingSvc.state] ?? 0) ? (svc.state ?? existingSvc.state) : existingSvc.state,
            sources: [...new Set([...existingSvc.sources, ...(svc.sources ?? [])])].sort(),
          },
        });
      }
      services++;
    }
    // Technologies attach to their host's asset (§34), deduped per asset+name.
    let technologies = 0;
    for (const tech of processed.technologies) {
      const assetId = tech.host ? assetIdByHost.get(tech.host) : undefined;
      if (!assetId) continue;
      const existing = await prisma.technology.findFirst({ where: { assetId, name: tech.name } });
      if (existing) {
        await prisma.technology.update({
          where: { id: existing.id },
          data: { version: tech.version ?? existing.version, category: tech.category ?? existing.category, source: tech.source ?? existing.source, confidence: tech.confidence ?? existing.confidence },
        });
      } else {
        await prisma.technology.create({ data: { assetId, name: tech.name, version: tech.version, category: tech.category, source: tech.source, confidence: tech.confidence } });
      }
      technologies++;
    }
    // Endpoints attach to their host's asset; deduped per asset+URL so
    // repeated stages/scans refresh status + parameter names (§33).
    // Prompt 6: response-classification metadata, route classification and
    // the full provenance list refresh the same way (§16/§26).
    let endpoints = 0;
    const endpointIdByUrl = new Map<string, string>();
    for (const ep of processed.endpoints) {
      const host = hostOf(ep.url);
      // Fallback (Prompt 9): endpoints from stages whose own result
      // carried no assets (route discovery, traffic import) attach to
      // the asset row earlier stages already recorded for this target.
      let assetId = assetIdByHost.get(host);
      if (!assetId) {
        const existingAsset = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host } });
        if (existingAsset) { assetId = existingAsset.id; assetIdByHost.set(host, assetId); }
      }
      if (!assetId) continue;
      const existingEp = await prisma.endpoint.findFirst({ where: { assetId, url: ep.url } });
      if (existingEp) {
        const updated = await prisma.endpoint.update({
          where: { id: existingEp.id },
          data: {
            statusCode: ep.statusCode ?? existingEp.statusCode,
            parameterNames: [...new Set([...existingEp.parameterNames, ...ep.parameterNames])].sort(),
            source: ep.source ?? existingEp.source, scopeStatus: ep.scopeStatus,
            contentType: ep.contentType ?? existingEp.contentType,
            contentLength: ep.contentLength ?? existingEp.contentLength,
            title: ep.title ?? existingEp.title,
            redirectLocation: ep.redirectLocation ?? existingEp.redirectLocation,
            endpointType: ep.endpointType !== "UNKNOWN" ? ep.endpointType : existingEp.endpointType,
            classification: ep.classification ?? existingEp.classification,
            sources: [...new Set([...existingEp.sources, ...ep.sources])].sort(),
          },
        });
        endpointIdByUrl.set(ep.url, updated.id);
      } else {
        const created = await prisma.endpoint.create({
          data: {
            assetId, url: ep.url, method: ep.method, statusCode: ep.statusCode, parameterNames: ep.parameterNames,
            source: ep.source, scopeStatus: ep.scopeStatus, contentType: ep.contentType, contentLength: ep.contentLength,
            title: ep.title, redirectLocation: ep.redirectLocation, endpointType: ep.endpointType,
            classification: ep.classification, sources: ep.sources,
          },
        });
        endpointIdByUrl.set(ep.url, created.id);
      }
      endpoints++;
    }
    // Parameters (Prompt 6 §27): upserted on (endpoint, name, location) —
    // NAMES and provenance only; a parameter value is never written.
    let parameters = 0;
    for (const param of processed.parameters) {
      const endpointId = endpointIdByUrl.get(param.endpointUrl) ?? endpointIdByUrl.get(param.endpointUrl.split("?")[0]!);
      if (!endpointId) continue;
      await prisma.endpointParameter.upsert({
        where: { endpointId_name_location: { endpointId, name: param.name, location: param.location } },
        create: { endpointId, name: param.name, location: param.location, sources: param.sources, confidence: param.confidence },
        update: { sources: param.sources, confidence: param.confidence },
      });
      parameters++;
    }
    // Forms (§33): structure metadata, refreshed per endpoint+method.
    let forms = 0;
    for (const form of processed.forms) {
      const endpointId = endpointIdByUrl.get(form.endpointUrl);
      if (!endpointId) continue;
      const existingForm = await prisma.endpointForm.findFirst({ where: { endpointId, method: form.method } });
      if (existingForm) {
        await prisma.endpointForm.update({
          where: { id: existingForm.id },
          data: { fieldNames: [...new Set([...existingForm.fieldNames, ...form.fieldNames])].sort(), encodingType: form.encodingType ?? existingForm.encodingType, source: form.source ?? existingForm.source },
        });
      } else {
        await prisma.endpointForm.create({ data: { endpointId, method: form.method, fieldNames: form.fieldNames, encodingType: form.encodingType, source: form.source } });
      }
      forms++;
    }
    let findings = 0;
    for (const f of processed.findings) {
      // Prompt 7 §16/§17/§29: the full normalized record persists — CVE /
      // CWE / CVSS only when present on the processed finding (sourced by
      // the tool output or the curated taxonomy upstream, never invented
      // here). Every source gets its own evidence row; references are
      // validated upstream by sanitizeReferenceUrl (§54).
      const created = await prisma.finding.create({
        data: {
          workspaceId: scan.workspaceId, scanId, assetId: f.host ? assetIdByHost.get(f.host) : undefined,
          title: f.title, description: f.description, severity: f.severity as never, confidence: f.confidence,
          host: f.host, endpoint: f.endpoint, fingerprint: f.fingerprint, isMock: f.isMock,
          toolExecutionId: executionId, status: "OPEN", verificationStatus: "UNVERIFIED",
          vulnClass: f.vulnClass, sources: f.sources,
          cve: f.cve, cwe: f.cwe, owaspCategory: f.owaspCategory,
          cvssScore: f.cvssScore, cvssVector: f.cvssVector,
          port: f.port, protocol: f.protocol, parameter: f.parameter,
          technicalImpact: f.technicalImpact, businessImpact: f.businessImpact, remediation: f.remediation,
          evidence: {
            create: f.evidenceRows.map((e) => ({
              sourceTool: e.sourceTool, evidenceType: "TEXT", summary: e.summary,
              fingerprint: e.fingerprint, matchedAt: e.matchedAt,
              metadata: (e.metadata ?? undefined) as never,
            })),
          },
          references: { create: f.references.map((r) => ({ type: r.type, label: r.label, url: r.url })) },
          history: { create: { workspaceId: scan.workspaceId, event: "CREATED", metadata: { sourceTool: f.sourceTool } as never } },
        },
      });
      void created;
      findings++;
    }
    // HTTP transactions (Prompt 8 §25/§26): metadata, hashes, sizes,
    // artifact references and redacted display copies — raw bodies are
    // never written to Postgres.
    let transactions = 0;
    for (const tx of processed.transactions) {
      await prisma.httpTransaction.create({
        data: {
          scanId, workspaceId: scan.workspaceId,
          assetId: assetIdByHost.get(tx.host),
          endpointId: endpointIdByUrl.get(tx.url) ?? endpointIdByUrl.get(tx.url.split("?")[0]!),
          toolExecutionId: executionId,
          method: tx.method, url: tx.url, host: tx.host, statusCode: tx.statusCode,
          source: tx.source, scopeStatus: tx.scopeStatus, apiKind: tx.apiKind,
          requestHash: tx.requestHash, responseHash: tx.responseHash,
          requestSize: tx.requestSize, responseSize: tx.responseSize,
          requestArtifactRef: tx.requestArtifactRef, responseArtifactRef: tx.responseArtifactRef,
          requestRedacted: tx.requestRedacted, responseRedacted: tx.responseRedacted,
          ...(tx.observedAt ? { observedAt: new Date(tx.observedAt) } : {}),
        },
      });
      transactions++;
    }
    // WebSocket inventory (§49): upserted per scan+URL.
    let webSockets = 0;
    for (const ws of processed.webSockets) {
      await prisma.webSocketEndpoint.upsert({
        where: { scanId_url: { scanId, url: ws.url } },
        create: { scanId, workspaceId: scan.workspaceId, url: ws.url, origin: ws.origin, subprotocol: ws.subprotocol, source: ws.source, scopeStatus: ws.scopeStatus, authPresent: ws.authPresent },
        update: { origin: ws.origin, subprotocol: ws.subprotocol, source: ws.source, scopeStatus: ws.scopeStatus, authPresent: ws.authPresent ?? undefined },
      });
      webSockets++;
    }
    // API services (Prompt 9 §3/§37): upserted per asset+baseUrl. The
    // owning asset is resolved from this result, from earlier stages'
    // rows, or created as a recorded (never promoted) asset — an
    // out-of-scope API base is stored with its verdict, exactly like a
    // discovered asset (§5).
    let apiServices = 0;
    const resolveAssetId = async (host: string, scopeStatus: string): Promise<string | undefined> => {
      const known = assetIdByHost.get(host);
      if (known) return known;
      const existing = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host } });
      if (existing) { assetIdByHost.set(host, existing.id); return existing.id; }
      const created = await prisma.asset.create({
        data: { workspaceId: scan.workspaceId, targetId: scan.assessment.targetId, host, type: "HOST", scopeStatus, sources: [], discoveredByScanId: scanId },
      });
      assetIdByHost.set(host, created.id);
      return created.id;
    };
    for (const svc of processed.apiServices) {
      const assetId = await resolveAssetId(svc.host, svc.scopeStatus);
      if (!assetId) continue;
      await prisma.apiService.upsert({
        where: { assetId_baseUrl: { assetId, baseUrl: svc.baseUrl } },
        create: {
          workspaceId: scan.workspaceId, assetId, baseUrl: svc.baseUrl, host: svc.host, apiType: svc.apiType,
          version: svc.version, authenticationType: svc.authenticationType, specificationId: svc.specificationId,
          source: svc.source, scopeStatus: svc.scopeStatus,
        },
        update: {
          apiType: svc.apiType, version: svc.version, authenticationType: svc.authenticationType,
          specificationId: svc.specificationId, source: svc.source, scopeStatus: svc.scopeStatus, lastSeen: new Date(),
        },
      });
      apiServices++;
    }
    // GraphQL services (§26): upserted per workspace+endpoint.
    let graphqlServices = 0;
    for (const g of processed.graphqlServices) {
      const assetId = await resolveAssetId(g.host, g.scopeStatus);
      await prisma.graphqlService.upsert({
        where: { workspaceId_endpointUrl: { workspaceId: scan.workspaceId, endpointUrl: g.endpointUrl } },
        create: {
          workspaceId: scan.workspaceId, assetId, endpointUrl: g.endpointUrl, schemaAvailable: g.schemaAvailable,
          queries: g.queries, mutations: g.mutations, subscriptions: g.subscriptions, types: g.types,
          authenticationRequired: g.authenticationRequired, source: g.source, scopeStatus: g.scopeStatus,
        },
        update: {
          assetId, schemaAvailable: g.schemaAvailable, queries: g.queries, mutations: g.mutations,
          subscriptions: g.subscriptions, types: g.types, authenticationRequired: g.authenticationRequired,
          source: g.source, scopeStatus: g.scopeStatus,
        },
      });
      graphqlServices++;
    }
    // JWT profiles (§25): metadata only — fingerprint, header and
    // redacted claims. Deduped per scan+fingerprint; the raw token does
    // not exist in any processed shape, so nothing secret can land here.
    let jwtProfiles = 0;
    for (const p of processed.jwtProfiles) {
      const existing = await prisma.jwtProfile.findFirst({ where: { scanId, fingerprint: p.fingerprint } });
      if (existing) continue;
      await prisma.jwtProfile.create({
        data: {
          workspaceId: scan.workspaceId, scanId, targetId: scan.assessment.targetId,
          fingerprint: p.fingerprint, algorithm: p.algorithm, tokenType: p.tokenType, keyId: p.keyId,
          issuer: p.issuer, audience: p.audience ?? [], source: p.source, host: p.host, endpoint: p.endpoint,
          lifetimeSeconds: p.lifetimeSeconds,
          claimsSummary: p.claimsSummary as never,
          ...(p.expiresAt ? { expiresAt: new Date(p.expiresAt) } : {}),
          ...(p.notBefore ? { notBefore: new Date(p.notBefore) } : {}),
          ...(p.issuedAt ? { issuedAt: new Date(p.issuedAt) } : {}),
        },
      });
      jwtProfiles++;
    }
    // Packet captures (Prompt 10 §43/§74): METADATA rows only — the
    // bytes are the execution's object-storage artifact; storageKey
    // points at it, and raw access is VIEW_RAW_PCAP-gated + audited at
    // the API layer (§47). Deduped per scan+storageKey.
    let packetCaptures = 0;
    for (const cap of processed.packetCaptures) {
      const existingCap = await prisma.packetCaptureArtifact.findFirst({ where: { scanId, storageKey: cap.artifactRef } });
      if (existingCap) continue;
      await prisma.packetCaptureArtifact.create({
        data: {
          workspaceId: scan.workspaceId, scanId, toolExecutionId: executionId,
          assetId: cap.assetHost ? assetIdByHost.get(cap.assetHost) : undefined,
          format: cap.format, source: cap.source, storageKey: cap.artifactRef,
          sha256: cap.sha256, sizeBytes: cap.sizeBytes, durationSeconds: cap.durationSeconds,
          interfaceName: cap.interfaceName,
        },
      });
      packetCaptures++;
    }
    return { assets: processed.assets.length, findings, endpoints, services, technologies, parameters, forms, transactions, webSockets, apiServices, graphqlServices, jwtProfiles, packetCaptures };
  }

  /** Prompt 10 platform hook (§5/§25/§62): canonicalize the scan's CIDR
   *  target, apply the CIDR size policy and persist BOUNDED chunk rows
   *  for checkpointing/distribution — never one row per host. A
   *  hard-denied size records no chunks and reports mode DENIED so the
   *  runner can emit the protected-target event. */
  async expandNetworkTargets(scanId: string): Promise<{ mode: string; hosts: number; chunks: number; totalHosts: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const targetValue = graph.assessment.target.value;
    const verdict = new CidrPolicyService().evaluate(targetValue, { administratorApproved: false });
    if (!verdict) return null; // not a CIDR target — nothing to expand
    if (verdict.approval === "DENY") {
      return { mode: "DENIED", hosts: 0, chunks: 0, totalHosts: verdict.hostCount };
    }
    const expansion = expandCidrTargets(targetValue);
    if (!expansion) return null;
    for (const chunk of expansion.chunks) {
      await prisma.networkScanChunk.upsert({
        where: { scanId_chunkId: { scanId, chunkId: chunk.chunkId } },
        create: {
          workspaceId: graph.workspaceId, scanId, chunkId: chunk.chunkId,
          rangeStart: chunk.rangeStart, rangeEnd: chunk.rangeEnd, hostCount: chunk.hostCount, status: "PENDING",
        },
        update: { rangeStart: chunk.rangeStart, rangeEnd: chunk.rangeEnd, hostCount: chunk.hostCount },
      });
    }
    return expansion.kind === "LIST"
      ? { mode: "LIST", hosts: expansion.hosts.length, chunks: expansion.chunks.length, totalHosts: expansion.hosts.length }
      : { mode: "RANGES", hosts: 0, chunks: expansion.chunks.length, totalHosts: expansion.totalHosts };
  }

  /** NORMALIZATION stage hook (§45/§46): counts from persisted findings. */
  async summarizeFindings(scanId: string): Promise<Record<string, unknown> | null> {
    const rows = await prisma.finding.findMany({ where: { scanId }, select: { severity: true } });
    if (rows.length === 0) return null;
    const bySeverity: Record<string, number> = {};
    for (const r of rows) bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
    return { totalFindings: rows.length, bySeverity };
  }

  /** CORRELATION stage hook (§18–§22): canonicalize the scan's findings.
   *  Duplicates are marked duplicateOfId=canonical and their evidence rows
   *  are re-homed to the canonical finding — evidence is NEVER deleted
   *  (§20). Canonical rows absorb merged sources/confidence/risk. */
  async correlateScanFindings(scanId: string): Promise<{ canonical: number; duplicates: number; stats: Record<string, unknown> } | null> {
    const rows = await prisma.finding.findMany({
      where: { scanId },
      include: { evidence: true, references: true, asset: { select: { criticality: true } } },
      orderBy: { createdAt: "asc" },
    });
    if (rows.length === 0) return null;
    const processed: ProcessedFinding[] = rows.map((r) => ({
      title: r.title, description: r.description, severity: r.severity, confidence: r.confidence,
      host: r.host ?? undefined, endpoint: r.endpoint ?? undefined, fingerprint: r.fingerprint ?? r.id,
      isMock: r.isMock, sourceTool: r.evidence[0]?.sourceTool ?? "unknown", toolExecutionId: r.toolExecutionId ?? "",
      evidenceSummary: r.evidence[0]?.summary ?? "",
      vulnClass: r.vulnClass ?? undefined, sources: r.sources,
      evidenceRows: r.evidence.map((e) => ({ sourceTool: e.sourceTool, summary: e.summary ?? "", fingerprint: e.fingerprint ?? undefined, matchedAt: e.matchedAt ?? undefined })),
      references: r.references.map((x) => ({ type: x.type, label: x.label, url: x.url })),
      cve: r.cve ?? undefined, cwe: r.cwe ?? undefined, owaspCategory: r.owaspCategory ?? undefined,
      cvssScore: r.cvssScore ?? undefined, cvssVector: r.cvssVector ?? undefined,
      port: r.port ?? undefined, protocol: r.protocol ?? undefined, parameter: r.parameter ?? undefined,
      technicalImpact: r.technicalImpact ?? undefined, businessImpact: r.businessImpact ?? undefined,
      remediation: r.remediation ?? undefined,
    }));
    const criticality = rows.find((r) => r.asset)?.asset?.criticality ?? "UNSPECIFIED";
    const { findings: canonical, stats } = correlateProcessedFindings(processed, { assetCriticality: criticality, maxFindings: 1000 });
    // Each canonical finding's evidence rows carry the SOURCE fingerprints
    // of its member rows (correlateProcessedFindings preserves them), so
    // members map back to persisted rows deterministically.
    const rowByFingerprint = new Map(rows.map((r) => [r.fingerprint ?? r.id, r]));
    let duplicates = 0;
    for (const c of canonical) {
      const memberFingerprints = c.evidenceRows.map((e) => e.fingerprint).filter((x): x is string => !!x);
      const memberRows = memberFingerprints.map((fp) => rowByFingerprint.get(fp)).filter((r): r is NonNullable<typeof r> => !!r);
      const primaryRow = memberRows[0];
      if (!primaryRow) continue;
      await prisma.finding.update({
        where: { id: primaryRow.id },
        data: {
          fingerprint: c.fingerprint, sources: c.sources, confidence: c.confidence,
          confidenceBand: c.confidenceBand, verificationStatus: (c.verificationStatus ?? "UNVERIFIED") as never,
          riskScore: c.riskScore, riskBand: c.riskBand, riskExplanation: (c.riskExplanation ?? undefined) as never,
          severity: c.severity as never,
          cve: c.cve ?? primaryRow.cve,
          cwe: c.cwe ?? primaryRow.cwe,
          cvssScore: c.cvssScore ?? primaryRow.cvssScore, remediation: c.remediation ?? primaryRow.remediation,
        },
      });
      // Re-home duplicate evidence + mark duplicates (§20: never delete).
      for (const member of memberRows.slice(1)) {
        await prisma.findingEvidence.updateMany({ where: { findingId: member.id }, data: { findingId: primaryRow.id } });
        await prisma.finding.update({ where: { id: member.id }, data: { duplicateOfId: primaryRow.id } });
        await prisma.findingHistory.create({ data: { findingId: member.id, workspaceId: member.workspaceId, event: "CORRELATED", metadata: { canonicalFindingId: primaryRow.id } as never } });
        duplicates++;
      }
      if (c.sources.length > 1) {
        await prisma.findingHistory.create({ data: { findingId: primaryRow.id, workspaceId: primaryRow.workspaceId, event: "CORRELATED", metadata: { sources: c.sources } as never } });
      }
    }
    return { canonical: canonical.length, duplicates, stats: stats as unknown as Record<string, unknown> };
  }

  /** RISK stage hook (§34/§35): recompute risk for canonical findings
   *  (duplicates keep pointing at their canonical row). */
  async recalculateFindingRisk(scanId: string): Promise<{ updated: number } | null> {
    const rows = await prisma.finding.findMany({ where: { scanId, duplicateOfId: null }, include: { asset: { select: { criticality: true } } } });
    if (rows.length === 0) return null;
    let updated = 0;
    for (const r of rows) {
      const risk = computeRisk({
        severity: r.severity as never, cvssScore: r.cvssScore ?? undefined, confidence: r.confidence,
        assetCriticality: (r.asset?.criticality ?? "UNSPECIFIED") as never,
        verificationStatus: r.verificationStatus as never,
      });
      await prisma.finding.update({ where: { id: r.id }, data: { riskScore: risk.score, riskBand: risk.band, riskExplanation: risk.explanation as never } });
      updated++;
    }
    return { updated };
  }

  // ---------- Prompt 9 platform-stage hooks ----------

  /** API_DISCOVERY hook (§5): counts of the consolidated API inventory
   *  for this scan's target. */
  async consolidateApiServices(scanId: string): Promise<{ services: number; endpoints: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const assets = await prisma.asset.findMany({ where: { targetId: graph.assessment.targetId }, select: { id: true } });
    if (assets.length === 0) return null;
    const ids = assets.map((a) => a.id);
    const [services, endpoints] = await Promise.all([
      prisma.apiService.count({ where: { assetId: { in: ids } } }),
      prisma.endpoint.count({ where: { assetId: { in: ids } } }),
    ]);
    if (services === 0 && endpoints === 0) return null;
    return { services, endpoints };
  }

  /** SPEC_IMPORT hook (§6): what the guarded import store holds for
   *  this target. */
  async summarizeApiSpecifications(scanId: string): Promise<{ specifications: number; operations: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const specs = await prisma.apiSpecification.findMany({
      where: { targetId: graph.assessment.targetId },
      select: { operationCount: true },
    });
    if (specs.length === 0) return null;
    return { specifications: specs.length, operations: specs.reduce((n, s) => n + (s.operationCount ?? 0), 0) };
  }

  /** AUTH_MAPPING hook (§19–§21): registered contexts + services with a
   *  declared authentication type. References only — no secret is
   *  resolved or used here. */
  async mapApiAuthentication(scanId: string): Promise<{ contexts: number; servicesWithAuth: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const assets = await prisma.asset.findMany({ where: { targetId: graph.assessment.targetId }, select: { id: true } });
    const [contexts, servicesWithAuth] = await Promise.all([
      prisma.apiAuthContext.count({ where: { workspaceId: graph.workspaceId } }),
      assets.length === 0 ? Promise.resolve(0) : prisma.apiService.count({
        where: { assetId: { in: assets.map((a) => a.id) }, authenticationType: { notIn: ["NONE"] }, NOT: { authenticationType: null } },
      }),
    ]);
    if (contexts === 0 && servicesWithAuth === 0) return null;
    return { contexts, servicesWithAuth };
  }

  /** JWT_ANALYSIS hook (§22–§25): resolve the workspace's registered
   *  credential REFERENCES (API auth contexts + session profiles) inside
   *  this trusted boundary; values that parse as JWTs are inspected.
   *  Only fingerprints + redacted metadata persist — the token itself is
   *  dropped when this function returns. Findings flow into the scan's
   *  finding set ahead of NORMALIZATION/CORRELATION. */
  async analyzeJwtProfiles(scanId: string): Promise<{ tokens: number; findings: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const budget = clampDiscoveryBudget();
    const [contexts, sessions] = await Promise.all([
      prisma.apiAuthContext.findMany({ where: { workspaceId: graph.workspaceId }, select: { credentialReference: true } }),
      prisma.sessionProfile.findMany({ where: { workspaceId: graph.workspaceId }, select: { credentialReference: true } }),
    ]);
    const references = [...new Set([...contexts, ...sessions].map((r) => r.credentialReference).filter((v): v is string => !!v))];
    if (references.length === 0) return null;
    const resolver = new EnvSecretResolver();
    const tokens: string[] = [];
    for (const reference of references) {
      if (tokens.length >= budget.maxJwtTokensAnalyzed) break;
      const value = await resolver.resolve(reference).catch(() => undefined);
      // A resolved value is a candidate ONLY when it is JWT-shaped; any
      // other secret (passwords, API keys) is never inspected or stored.
      if (value && value.split(".").length === 3) tokens.push(value);
    }
    if (tokens.length === 0) return null;
    const adapter = new JwtToolAdapter();
    const parsed = adapter.inspectTokens({ tokens, host: hostOf(graph.assessment.target.value) });
    const normalized = await adapter.normalize(parsed);
    // Persist profiles (deduped per scan+fingerprint).
    for (const p of normalized.jwtProfiles ?? []) {
      const existing = await prisma.jwtProfile.findFirst({ where: { scanId, fingerprint: p.fingerprint } });
      if (existing) continue;
      await prisma.jwtProfile.create({
        data: {
          workspaceId: graph.workspaceId, scanId, targetId: graph.assessment.targetId,
          fingerprint: p.fingerprint, algorithm: p.algorithm, tokenType: p.tokenType, keyId: p.keyId,
          issuer: p.issuer, audience: p.audience ?? [], source: p.source, host: p.host, endpoint: p.endpoint,
          lifetimeSeconds: p.lifetimeSeconds, claimsSummary: p.claimsSummary as never,
          ...(p.expiresAt ? { expiresAt: new Date(p.expiresAt) } : {}),
          ...(p.notBefore ? { notBefore: new Date(p.notBefore) } : {}),
          ...(p.issuedAt ? { issuedAt: new Date(p.issuedAt) } : {}),
        },
      });
    }
    // Persist findings through the same normalized shape the tool
    // stages produce (fingerprint + evidence + history), ahead of the
    // NORMALIZATION stage. toolExecutionId stays null: platform stage.
    let findings = 0;
    for (const f of normalized.findings) {
      const v = f as typeof f & { vulnClass?: string; evidenceDetail?: { checkId?: string; metadata?: Record<string, string> } };
      const asset = f.host ? await prisma.asset.findFirst({ where: { targetId: graph.assessment.targetId, host: f.host } }) : null;
      await prisma.finding.create({
        data: {
          workspaceId: graph.workspaceId, scanId, assetId: asset?.id,
          title: f.title, description: f.description, severity: f.severity as never, confidence: f.confidence,
          host: f.host, endpoint: f.endpoint, fingerprint: f.sourceFingerprint, isMock: false,
          toolExecutionId: null, status: "OPEN", verificationStatus: "UNVERIFIED",
          vulnClass: v.vulnClass, sources: [f.sourceTool], cwe: f.cwe, owaspCategory: f.owaspCategory,
          remediation: f.remediation,
          evidence: {
            create: [{
              sourceTool: f.sourceTool, evidenceType: "TEXT", summary: f.evidence ?? "",
              fingerprint: f.sourceFingerprint, metadata: (v.evidenceDetail?.metadata ?? undefined) as never,
            }],
          },
          history: { create: { workspaceId: graph.workspaceId, event: "CREATED", metadata: { sourceTool: f.sourceTool, stage: "JWT_ANALYSIS" } as never } },
        },
      });
      findings++;
    }
    return { tokens: (normalized.jwtProfiles ?? []).length, findings };
  }

  /** WEBSOCKET_INVENTORY hook (§31/§32): counts from this scan's
   *  persisted WebSocket inventory. */
  async inventoryWebSockets(scanId: string): Promise<{ webSockets: number; authenticated: number } | null> {
    const rows = await prisma.webSocketEndpoint.findMany({ where: { scanId }, select: { authPresent: true } });
    if (rows.length === 0) return null;
    return { webSockets: rows.length, authenticated: rows.filter((r) => r.authPresent).length };
  }

  async recordDeadLetter(entry: { jobId: string; queue: string; scanId: string; stageId: string; executionId: string; errorCategory: string; errorMessage: string; attempts: number }): Promise<void> {
    await prisma.deadLetterJob.create({ data: entry });
  }

  async isCancelled(scanId: string): Promise<boolean> {
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, select: { status: true } });
    return scan?.status === "CANCELLED" || scan?.status === "CANCELLING";
  }

  async isPaused(scanId: string): Promise<boolean> {
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, select: { status: true } });
    return scan?.status === "PAUSED" || scan?.status === "PAUSING";
  }

  // ---------- ScanRunStore ----------
  async loadScanRun(scanId: string): Promise<ScanRunRecord | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.plan || !graph.assessment) return null;
    const scopeParse = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
    const target = graph.assessment.target;
    return {
      plan: graph.plan.plan as unknown as ScanPlan,
      scanStatus: graph.status,
      progress: graph.progress,
      gate: {
        auth: {
          organizationId: graph.workspace.organizationId,
          workspaceId: graph.workspaceId,
          targetId: target.id,
          targetOrganizationId: graph.workspace.organizationId,
          assessmentId: graph.assessmentId,
          scanId,
          verificationStatus: target.verified ? "VERIFIED" : "PENDING",
          approvalStatus: graph.assessment.status === "APPROVED" ? "APPROVED" : "PENDING",
          requestedBy: graph.requestedBy,
        },
        targetHost: hostOf(target.value),
        scopeRules: scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
        targetExists: true,
        targetWorkspaceId: graph.workspaceId,
        workspaceId: graph.workspaceId,
        targetVerified: target.verified,
        assessmentApproved: graph.assessment.status === "APPROVED",
        scopeValid: scopeParse.success,
      },
    };
  }

  async stageStatuses(scanId: string): Promise<Map<string, string>> {
    const stages = await prisma.scanStage.findMany({ where: { scanId } });
    return new Map(stages.map((s) => [s.type as string, s.status as string]));
  }

  async updateScan(scanId: string, patch: Record<string, unknown>): Promise<void> {
    await prisma.scan.update({ where: { id: scanId }, data: patch as never });
  }

  async updateStage(scanId: string, stageType: string, patch: Record<string, unknown>): Promise<void> {
    await prisma.scanStage.updateMany({ where: { scanId, type: stageType as never }, data: patch as never });
  }

  async ensureExecution(scanId: string, stageType: string, adapterSlug: string, attempt: number): Promise<{ id: string; status: string }> {
    // Slug-scoped key (Prompt 5): multi-adapter stages get one execution
    // per adapter instead of colliding on the stage-only key.
    const key = idempotencyKey(scanId, stageType, attempt, adapterSlug);
    const existing = await prisma.toolExecution.findUnique({ where: { idempotencyKey: key } });
    if (existing) return { id: existing.id, status: existing.status };
    const tool = await prisma.tool.findUnique({ where: { slug: adapterSlug } });
    if (!tool) throw new Error(`Tool catalog row missing for adapter ${adapterSlug}`);
    const adapter = await prisma.toolAdapter.findFirst({ where: { toolId: tool.id }, orderBy: { createdAt: "asc" } });
    const stage = await prisma.scanStage.findFirst({ where: { scanId, type: stageType as never } });
    const created = await prisma.toolExecution.create({
      data: {
        scanId, scanStageId: stage?.id, toolId: tool.id, toolAdapterId: adapter?.id,
        idempotencyKey: key, attempt, status: "QUEUED",
      },
    });
    return { id: created.id, status: created.status };
  }

  async markReportPending(scanId: string): Promise<void> {
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, select: { workspaceId: true, requestedBy: true } });
    if (!scan) return;
    const existing = await prisma.report.findFirst({ where: { scanId, status: "PENDING" } });
    if (!existing) {
      await prisma.report.create({
        data: { workspaceId: scan.workspaceId, scanId, format: "PDF", status: "PENDING", generatedBy: scan.requestedBy },
      });
    }
  }
}
