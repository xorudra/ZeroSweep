import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import {
  assessDanglingDns, certificateState, classifyInternetExposure, compareSnapshots,
  deriveRiskSignals, detectWildcard, diffCertificate, diffDnsSnapshots, dnsSnapshotHash,
  domainIdentity, nextLifecycleOnObservation, normalizeCertificateFingerprint, normalizeDomain,
  normalizeHistoricalUrls, normalizeIp, normalizeTechnologyName, normalizeUrl, resolveOwnership,
  resolveTechnologies, sensitiveServiceClass, type DnsRecord, type EasmSnapshot,
  type OwnershipEvidenceInput,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { AlertService } from "../../soc/alerts/alert.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireEasmPermission } from "../permissions";
import { EASM_TRANSPORT, type EasmDiscoveryTransport } from "./transport";

type Row = Record<string, unknown>;

const PASSIVE_SOURCES = ["AMASS_PASSIVE", "SUBFINDER", "ASSETFINDER", "FINDOMAIN", "CERT_TRANSPARENCY"] as const;
const ACTIVE_SOURCES = ["DNS_RESOLUTION", "TLS_HANDSHAKE", "HTTP_PROBE", "SERVICE_DISCOVERY"] as const;

/**
 * Discovery pipeline (Prompt 29 §12–§64, §86): Sources → Normalize →
 * Dedupe → DNS/Cert/Service/HTTP/Technology intelligence → Ownership
 * → Exposure → Drift → Signals. The authorization boundary is
 * enforced at INGESTION time: payloads from ACTIVE sources are only
 * accepted for hosts under a root whose active testing is separately
 * authorized, and service observations only for ports in the
 * approved profile (§41/§43/§139). Passive results are candidates —
 * never authorized targets (§13).
 */
@Injectable()
export class EasmDiscoveryService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly alerts: AlertService,
    @Inject(EASM_TRANSPORT) private readonly transport: EasmDiscoveryTransport,
  ) {}

  private async auditSafe(entry: Parameters<AuditService["record"]>[0]) {
    await this.audit.record(entry).catch(() => undefined);
  }

  /** Longest-suffix root match for a domain; exact match for IPs. */
  private matchRoot(roots: Row[], value: string, type: string): Row | null {
    if (type === "IP") return roots.find((r) => r.type === "IP" && r.value === value) ?? null;
    let best: Row | null = null;
    for (const r of roots) {
      if (r.type !== "DOMAIN") continue;
      const root = r.value as string;
      if (value === root || value.endsWith(`.${root}`)) {
        if (!best || root.length > (best.value as string).length) best = r;
      }
    }
    return best;
  }

  private rootAuthorizedActive(root: Row | null): boolean {
    return !!root && root.activeTestingStatus !== "NOT_AUTHORIZED" && root.authorizationStatus === "VERIFIED";
  }

  async runDiscovery(user: RequestUser, workspaceId: string, programId: string, input: { trigger?: string; sourceResults?: Array<Row>; limitSources?: string[] }) {
    requireEasmPermission(user, "RUN_EASM_DISCOVERY");
    const program = await this.prisma.easmProgram.findFirst({ where: { id: programId, workspaceId } });
    if (!program) throw new BadRequestException("EASM program not found in workspace");
    if (program.status === "PAUSED" || program.status === "ARCHIVED") {
      throw new BadRequestException(`Program is ${program.status} — discovery refused (§116)`);
    }
    const policy = (await this.prisma.easmDiscoveryPolicy.findFirst({ where: { workspaceId, programId } })) as Row | null;
    const profile = (await this.prisma.easmServiceDiscoveryProfile.findFirst({ where: { workspaceId, programId } })) as Row | null;
    const roots = (await this.prisma.easmRootAsset.findMany({ where: { workspaceId, programId } })) as Row[];
    const approvedPorts = new Set<number>((profile?.ports as number[] | undefined) ?? [80, 443]);

    // --- §116: auditable job created before any source runs.
    const run = await this.prisma.easmDiscoveryRun.create({
      data: { programId, workspaceId, status: "RUNNING", trigger: input.trigger ?? "MANUAL" },
    });
    await this.auditSafe({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EASM_DISCOVERY_STARTED", resourceType: "EasmDiscoveryRun", resourceId: run.id,
      metadata: { programId, trigger: input.trigger ?? "MANUAL" },
    });

    // --- Which sources does policy select? (§10/§11/§87)
    const selected: string[] = [];
    if (policy?.passiveDiscovery !== false) selected.push(...PASSIVE_SOURCES.filter((s) => s !== "CERT_TRANSPARENCY" || policy?.certificateDiscovery !== false));
    if (policy?.dnsResolution !== false) selected.push("DNS_RESOLUTION", "DNS_ZONE_OBSERVATION");
    if (policy?.certificateDiscovery !== false) selected.push("TLS_HANDSHAKE");
    if (policy?.httpProbing === true) selected.push("HTTP_PROBE");
    if (policy?.serviceDiscovery === true) selected.push("SERVICE_DISCOVERY");
    if (policy?.technologyDetection !== false) selected.push("TECHNOLOGY_DETECTION");
    if (policy?.historicalUrls === true) selected.push("HISTORICAL_URLS");
    // §88 multi-tier scheduling: a light tier runs only its source subset.
    if (input.limitSources) {
      for (let i = selected.length - 1; i >= 0; i--) {
        if (!input.limitSources.includes(selected[i]!)) selected.splice(i, 1);
      }
    }

    // --- Merge submitted recorded results with transport collection.
    const submitted = new Map<string, Row>();
    for (const r of input.sourceResults ?? []) submitted.set(r.source as string, r);
    const missing = selected.filter((s) => !submitted.has(s));
    const transportResults: import("./transport").EasmTransportResult[] = missing.length > 0
      ? await this.transport.collect({
          programId, workspaceId,
          rootAssets: roots.map((r) => ({ id: r.id as string, type: r.type as string, value: r.value as string, activeTestingStatus: r.activeTestingStatus as string })),
          sources: missing as never,
        }).catch((): import("./transport").EasmTransportResult[] => missing.map((s) => ({ source: s as never, status: "ERROR" as const, durationMs: 0, errorClass: "TRANSPORT_FAILURE" })))
      : [];
    const payloads = new Map<string, Row>();
    for (const t of transportResults) if (t.payload) payloads.set(t.source, t.payload as Row);
    for (const [k, v] of submitted) payloads.set(k, v);

    const anyActiveAuthorized = roots.some((r) => this.rootAuthorizedActive(r));
    const adapterRows: Row[] = [];
    let anyError = false;
    let anyNotConfigured = false;
    for (const source of selected) {
      const sub = submitted.get(source);
      const t = transportResults.find((x) => x.source === source);
      let status: string = t?.status ?? (sub ? (sub.status as string) ?? "OK" : "OK");
      let errorClass: string | undefined = t?.errorClass ?? (sub?.errorClass as string | undefined);
      if (ACTIVE_SOURCES.includes(source as never) && !anyActiveAuthorized) {
        // §13/§133/§136: no root is authorized for active testing —
        // the source does not run and any submitted payload is dropped.
        status = "SKIPPED_POLICY";
        errorClass = "ACTIVE_NOT_AUTHORIZED";
        payloads.delete(source);
      }
      if (status === "ERROR") anyError = true;
      if (status === "NOT_CONFIGURED") anyNotConfigured = true;
      adapterRows.push({
        runId: run.id, workspaceId, adapter: source, version: (sub?.version as string) ?? t?.version ?? null,
        status, durationMs: (sub?.durationMs as number) ?? t?.durationMs ?? 0,
        resultCount: 0, errorClass: errorClass ?? null,
      });
    }

    // Submitted sources the policy did NOT select are recorded as
    // SKIPPED_POLICY and their payloads are dropped (§10/§116): the
    // policy, not the submitter, decides what runs.
    for (const source of submitted.keys()) {
      if (!selected.includes(source)) {
        adapterRows.push({
          runId: run.id, workspaceId, adapter: source, version: (submitted.get(source)?.version as string) ?? null,
          status: "SKIPPED_POLICY", durationMs: 0, resultCount: 0, errorClass: "SOURCE_NOT_IN_POLICY",
        });
        payloads.delete(source);
      }
    }

    // --- Snapshot BEFORE ingestion (drift baseline for this run).
    const beforeSnapshot = await this.buildSnapshot(workspaceId, programId);

    const counters = { found: 0, created: 0, droppedActive: 0, droppedPort: 0, truncated: 0 };
    const touched = new Set<string>();
    const wildcardDomains = new Set<string>();
    const maxNew = (policy?.maxCandidatesPerRun as number | undefined) ?? 1000;
    // Corroboration map (§34): identity → sources that named it. A
    // candidate named by only one passive source under a wildcard
    // zone is treated as wildcard noise.
    const corroboration = new Map<string, Set<string>>();
    const noteSource = (identity: string | null, source: string) => {
      if (!identity) return;
      const set = corroboration.get(identity) ?? new Set<string>();
      set.add(source);
      corroboration.set(identity, set);
    };
    for (const [source, payload] of payloads) {
      for (const c of (payload.candidates as Row[] | undefined) ?? []) {
        noteSource(normalizeIp(c.value as string) ?? domainIdentity(c.value as string), source);
      }
      for (const cert of (payload.certificates as Row[] | undefined) ?? []) {
        noteSource(domainIdentity(cert.host as string), source);
        for (const san of (cert.sans as string[]) ?? []) noteSource(domainIdentity(san), "CERT_TRANSPARENCY");
      }
    }

    const upsertCandidate = async (rawValue: string, hintedType: string | undefined, source: string, confidence = 0.5, rawReference = ""): Promise<Row | null> => {
      let type = hintedType ?? "FQDN";
      let identity: string | null = null;
      let unicodeValue: string | null = null;
      let suspiciousIdn = false;
      const ip = normalizeIp(rawValue);
      if (ip) { type = "IP"; identity = ip; }
      else if (/^https?:\/\//i.test(rawValue)) {
        const u = normalizeUrl(rawValue);
        if (!u) return null;
        type = "URL"; identity = u.identity;
      } else {
        const d = normalizeDomain(rawValue);
        if (!d) return null;
        identity = d.ascii; unicodeValue = d.unicode !== d.ascii ? d.unicode : null; suspiciousIdn = d.suspiciousIdn;
        if (type === "DOMAIN") type = "FQDN";
      }
      if (!identity) return null;
      // §34: wildcard zones — an uncorroborated single-label child of a
      // wildcard domain is noise, not an asset.
      if (type === "FQDN") {
        const parent = identity.split(".").slice(1).join(".");
        if (wildcardDomains.has(parent) && (corroboration.get(identity)?.size ?? 0) < 2) {
          counters.truncated++;
          return null;
        }
      }
      const root = this.matchRoot(roots, identity, type);
      const existing = await this.prisma.easmAssetCandidate.findFirst({ where: { programId, normalizedValue: identity } });
      let candidate = existing as Row | null;
      if (!candidate) {
        if (counters.created >= maxNew) { counters.truncated++; return null; } // §125 backpressure
        candidate = await this.prisma.easmAssetCandidate.create({
          data: {
            programId, workspaceId, rootAssetId: (root?.id as string) ?? null, type,
            normalizedValue: identity, unicodeValue, suspiciousIdn,
            status: "NEW", lifecycle: "DISCOVERED",
            ownershipStatus: "UNKNOWN", ownershipConfidence: "UNKNOWN",
            activeTestingStatus: "NOT_AUTHORIZED", exposureState: "UNKNOWN",
            criticality: "UNSPECIFIED", missCount: 0,
            confidence, firstSeen: new Date(), lastSeen: new Date(),
          },
        }) as Row;
        counters.created++;
      } else {
        candidate = await this.prisma.easmAssetCandidate.update({
          where: { id: candidate.id as string },
          data: { lastSeen: new Date(), missCount: 0, lifecycle: (candidate.lifecycle as string) === "DISAPPEARED" ? "ACTIVE" : (candidate.lifecycle as string) },
        }) as Row;
      }
      counters.found++;
      touched.add(candidate.id as string);
      await this.prisma.assetDiscoveryObservation.create({
        data: {
          candidateId: candidate.id as string, workspaceId, programId,
          rootAssetId: (root?.id as string) ?? (candidate.rootAssetId as string) ?? null,
          source, confidence, rawReference,
          relationship: root ? "SUBDOMAIN_OF" : null,
        },
      });
      return candidate;
    };

    // --- Wildcard pre-pass (§34) from DNS payloads.
    for (const payload of payloads.values()) {
      for (const dns of (payload.dnsRecords as Row[] | undefined) ?? []) {
        if (dns.wildcardProbes) {
          const w = detectWildcard(dns.wildcardProbes as Array<{ label: string; addresses: string[] }>);
          if (w.wildcard) wildcardDomains.add(domainIdentity(dns.domain as string) ?? (dns.domain as string));
        }
      }
    }

    // --- Candidate ingestion from passive sources (§12/§30/§59).
    for (const [source, payload] of payloads) {
      for (const c of (payload.candidates as Row[] | undefined) ?? []) {
        await upsertCandidate(c.value as string, c.type as string | undefined, source, (c.confidence as number) ?? 0.5, (c.rawReference as string) ?? "");
      }
      for (const h of (payload.historicalUrls as Row[] | undefined) ?? []) {
        // §59/§60: historical URLs are candidates — normalized,
        // parameter values stripped, never auto-requested.
        const normalized = normalizeHistoricalUrls(h.urls as string[]);
        const rootCand = await upsertCandidate(h.rootDomain as string, "DOMAIN", source, 0.5, "historical-urls");
        if (rootCand) {
          for (const item of normalized) {
            await this.prisma.assetDiscoveryObservation.create({
              data: {
                candidateId: rootCand.id as string, workspaceId, programId, source,
                confidence: 0.4, rawReference: item.url, relationship: "HISTORICAL_URL",
                metadata: { classification: item.classification, parameterNames: item.parameterNames },
              },
            });
          }
        }
      }
    }

    // --- DNS intelligence (§25–§29).
    const dnsDrift: Array<{ candidateId: string; domain: string; events: ReturnType<typeof diffDnsSnapshots> }> = [];
    for (const payload of payloads.values()) {
      for (const dns of (payload.dnsRecords as Row[] | undefined) ?? []) {
        const domain = domainIdentity(dns.domain as string);
        if (!domain) continue;
        const candidate = await upsertCandidate(domain, "FQDN", "DNS_ZONE_OBSERVATION", 0.7);
        if (!candidate) continue;
        const records = dns.records as DnsRecord[];
        const hash = dnsSnapshotHash(domain, records);
        const previous = await this.prisma.dnsSnapshot.findFirst({
          where: { workspaceId, candidateId: candidate.id as string }, orderBy: { observedAt: "desc" },
        });
        await this.prisma.dnsSnapshot.create({
          data: { workspaceId, programId, candidateId: candidate.id as string, domain, records: records as never, source: "DNS_ZONE_OBSERVATION", hash },
        });
        if (previous) {
          const events = diffDnsSnapshots((previous.records as unknown as DnsRecord[]) ?? [], records);
          if (events.length > 0) dnsDrift.push({ candidateId: candidate.id as string, domain, events });
        }
        for (const rec of records) {
          if ((rec.type === "A" || rec.type === "AAAA") && normalizeIp(rec.value)) {
            const ipCand = await upsertCandidate(rec.value, "IP", "DNS_RESOLUTION", 0.8);
            if (ipCand) {
              await this.prisma.easmAssetRelationship.create({
                data: {
                  workspaceId, programId, fromType: "CANDIDATE", fromId: candidate.id as string,
                  toType: "CANDIDATE", toId: ipCand.id as string, kind: "DOMAIN_IP",
                  confidence: 0.9, source: "DNS_RESOLUTION",
                },
              }).catch(() => undefined);
            }
          }
        }
        const dangling = assessDanglingDns({ records, targetResolution: (dns.targetResolution as "NXDOMAIN" | "NO_ADDRESS" | "RESOLVES" | "UNKNOWN") ?? "UNKNOWN" });
        if (dangling.isCandidate) {
          const cname = records.find((r) => r.type === "CNAME");
          await this.prisma.danglingDnsCandidate.create({
            data: {
              workspaceId, programId, candidateId: candidate.id as string, domain,
              cnameTarget: cname?.value ?? "", service: dangling.service, evidence: dangling.evidence,
              status: "OPEN",
            },
          }).catch(() => undefined);
        }
      }
    }

    // --- Certificate intelligence (§35–§40).
    for (const [source, payload] of payloads) {
      for (const cert of (payload.certificates as Row[] | undefined) ?? []) {
        const fingerprint = normalizeCertificateFingerprint(cert.fingerprint as string);
        if (!fingerprint) continue;
        const host = domainIdentity(cert.host as string) ?? (cert.host as string);
        const hostCand = await upsertCandidate(host, "FQDN", source, 0.8);
        const notAfter = cert.notAfter ? new Date(cert.notAfter as string) : null;
        const state = notAfter ? certificateState(notAfter, new Date()) : "HEALTHY";
        const previousForHost = hostCand
          ? await this.prisma.easmCertificateObservation.findFirst({
              where: { workspaceId, candidateId: hostCand.id as string }, orderBy: { observedAt: "desc" },
            }).catch(() => null)
          : null;
        const record = await this.prisma.easmCertificate.upsert({
          where: { workspaceId_fingerprint: { workspaceId, fingerprint } },
          create: {
            workspaceId, fingerprint, subject: (cert.subject as string) ?? "", issuer: (cert.issuer as string) ?? "",
            sans: (cert.sans as string[]) ?? [], notBefore: cert.notBefore ? new Date(cert.notBefore as string) : null,
            notAfter, signatureAlgorithm: (cert.signatureAlgorithm as string) ?? "",
            keyType: (cert.keyType as string) ?? "", keyBits: (cert.keyBits as number) ?? null, state,
          },
          update: { state, lastSeen: new Date() },
        });
        if (hostCand) {
          await this.prisma.easmCertificateObservation.create({
            data: { workspaceId, certificateId: record.id, candidateId: hostCand.id as string, host, source: source === "CERT_TRANSPARENCY" ? "CERT_TRANSPARENCY" : "TLS_HANDSHAKE" },
          });
          const prevCert = previousForHost
            ? await this.prisma.easmCertificate.findFirst({ where: { workspaceId, id: previousForHost.certificateId as string } }).catch(() => null)
            : null;
          const changes = diffCertificate({
            host,
            before: prevCert ? { fingerprint: prevCert.fingerprint, state: prevCert.state as never } : null,
            after: { fingerprint, state: state as never },
          });
          for (const change of changes) {
            await this.prisma.easmDriftEvent.create({
              data: {
                workspaceId, programId, candidateId: hostCand.id as string, assetIdentity: host,
                type: "CERTIFICATE_CHANGED", before: { fingerprint: change.beforeFingerprint } as never,
                after: { fingerprint: change.afterFingerprint, change: change.kind } as never,
                severity: change.kind === "CERTIFICATE_EXPIRED" ? "HIGH" : "MEDIUM", status: "OPEN",
                fingerprint: `easm-drift:${host}:CERTIFICATE_CHANGED:${change.kind}:${fingerprint}`,
                evidence: { detail: change.detail } as never,
              },
            }).catch(() => undefined);
          }
        }
        // §37/§140: SAN entries create CANDIDATES ONLY.
        for (const san of (cert.sans as string[]) ?? []) {
          const sanCand = await upsertCandidate(san, "FQDN", "CERT_TRANSPARENCY", 0.4, `cert:${fingerprint.slice(0, 12)}`);
          if (sanCand && hostCand) {
            await this.prisma.assetDiscoveryObservation.create({
              data: {
                candidateId: sanCand.id as string, workspaceId, programId, source: "CERT_TRANSPARENCY",
                confidence: 0.4, rawReference: `cert:${fingerprint.slice(0, 12)}`, relationship: "SAN_OF",
              },
            }).catch(() => undefined);
          }
        }
      }
    }

    // --- Service + HTTP intelligence (ACTIVE sources, already gated).
    const serviceChanges: Array<{ candidateId: string; identity: string; added: Row[]; removed: Row[] }> = [];
    for (const [source, payload] of payloads) {
      for (const svc of (payload.services as Row[] | undefined) ?? []) {
        const host = domainIdentity(svc.host as string) ?? normalizeIp(svc.host as string) ?? (svc.host as string);
        const root = this.matchRoot(roots, host, normalizeIp(host) ? "IP" : "FQDN");
        if (!this.rootAuthorizedActive(root)) { counters.droppedActive++; continue; } // §136/§139 per-host gate
        if (!approvedPorts.has(svc.port as number)) { counters.droppedPort++; continue; } // §43 approved ports only
        const candidate = await upsertCandidate(host, undefined, source, 0.8);
        if (!candidate) continue;
        const existingObs = await this.prisma.serviceObservation.findFirst({
          where: { candidateId: candidate.id as string, port: svc.port as number, transport: (svc.transport as string) ?? "tcp" },
        });
        if (!existingObs) {
          await this.prisma.serviceObservation.create({
            data: {
              workspaceId, candidateId: candidate.id as string, ip: (svc.ip as string) ?? null,
              port: svc.port as number, transport: (svc.transport as string) ?? "tcp",
              service: (svc.service as string) ?? null, product: (svc.product as string) ?? null,
              version: (svc.version as string) ?? null, confidence: (svc.confidence as number) ?? 0.7,
              sensitiveClass: sensitiveServiceClass({ port: svc.port as number, service: svc.service as string }),
            },
          });
          const entry: { candidateId: string; identity: string; added: Row[]; removed: Row[] } = serviceChanges.find((s) => s.candidateId === (candidate.id as string)) ?? { candidateId: candidate.id as string, identity: host, added: [], removed: [] };
          entry.added.push(svc);
          if (!serviceChanges.includes(entry)) serviceChanges.push(entry);
        } else {
          await this.prisma.serviceObservation.update({ where: { id: existingObs.id as string }, data: { lastSeen: new Date() } });
        }
      }
      for (const http of (payload.httpObservations as Row[] | undefined) ?? []) {
        const host = domainIdentity(http.host as string) ?? (http.host as string);
        const root = this.matchRoot(roots, host, "FQDN");
        if (!this.rootAuthorizedActive(root)) { counters.droppedActive++; continue; } // §48/§137 redirect/probe gate
        const candidate = await upsertCandidate(host, undefined, source, 0.8);
        if (!candidate) continue;
        await this.prisma.httpExposureSnapshot.create({
          data: {
            workspaceId, programId, candidateId: candidate.id as string, url: http.url as string,
            status: (http.status as number) ?? null, title: (http.title as string) ?? null,
            headers: (http.headers as never) ?? {}, redirectTarget: (http.redirectTarget as string) ?? null,
            technologies: (http.technologies as string[]) ?? [],
            certificateFingerprint: http.certificateFingerprint ? normalizeCertificateFingerprint(http.certificateFingerprint as string) : null,
          },
        });
        // Redirects are RECORDED, never followed into scope (§48):
        // the redirect target becomes at most a passive observation.
        if (http.redirectTarget) {
          const targetHost = (() => { try { return new URL(http.redirectTarget as string).hostname; } catch { return null; } })();
          if (targetHost && domainIdentity(targetHost) && !this.matchRoot(roots, targetHost, "FQDN")) {
            await this.prisma.assetDiscoveryObservation.create({
              data: {
                candidateId: candidate.id as string, workspaceId, programId, source: "HTTP_PROBE",
                confidence: 0.3, rawReference: http.redirectTarget as string, relationship: "REDIRECTS_TO_OUT_OF_SCOPE",
              },
            }).catch(() => undefined);
          }
        }
      }
    }

    // --- Technology intelligence (§53–§58).
    const techByHost = new Map<string, Array<{ technology: string; source: string; version?: string | null; familyOnly?: boolean; category?: string }>>();
    const addTech = (host: string, t: { technology: string; source: string; version?: string | null; familyOnly?: boolean; category?: string }) => {
      const list = techByHost.get(host) ?? [];
      list.push(t);
      techByHost.set(host, list);
    };
    for (const [source, payload] of payloads) {
      for (const t of (payload.technologies as Row[] | undefined) ?? []) {
        addTech(domainIdentity(t.host as string) ?? (t.host as string), {
          technology: t.technology as string, source, version: (t.version as string) ?? null,
          familyOnly: t.familyOnly as boolean | undefined, category: t.category as string | undefined,
        });
      }
      for (const http of (payload.httpObservations as Row[] | undefined) ?? []) {
        for (const name of (http.technologies as string[]) ?? []) {
          addTech(domainIdentity(http.host as string) ?? (http.host as string), { technology: name, source, familyOnly: true });
        }
      }
    }
    for (const [host, observations] of techByHost) {
      const candidate = await upsertCandidate(host, undefined, "TECHNOLOGY_DETECTION", 0.6);
      if (!candidate) continue;
      for (const resolved of resolveTechnologies(observations)) {
        const category = observations.find((o) => normalizeTechnologyName(o.technology) === resolved.normalizedName)?.category ?? "OTHER";
        await this.prisma.technologyObservation.upsert({
          where: { candidateId_normalizedName: { candidateId: candidate.id as string, normalizedName: resolved.normalizedName } },
          create: {
            workspaceId, candidateId: candidate.id as string, technology: resolved.technology,
            normalizedName: resolved.normalizedName, version: resolved.version, category,
            confidence: resolved.confidence, sources: resolved.sources as never,
          },
          update: { version: resolved.version, confidence: resolved.confidence, sources: resolved.sources as never, lastSeen: new Date() },
        });
      }
    }

    // --- Ownership rules (§95/§96) + resolution (§65–§67).
    const rules = (await this.prisma.assetOwnershipRule.findMany({ where: { workspaceId } })) as Row[];
    for (const candidateId of touched) {
      const candidate = (await this.prisma.easmAssetCandidate.findFirst({ where: { id: candidateId, workspaceId } })) as Row | null;
      if (!candidate) continue;
      const evidence: OwnershipEvidenceInput[] = [];
      if (candidate.rootAssetId) evidence.push({ kind: "ROOT_RELATIONSHIP", reference: candidate.rootAssetId as string });
      const sanObs = await this.prisma.assetDiscoveryObservation.findFirst({ where: { workspaceId, candidateId, relationship: "SAN_OF" } });
      if (sanObs) evidence.push({ kind: "CERTIFICATE_SAN", reference: sanObs.id as string });
      for (const rule of rules) {
        const matches = rule.ruleType === "DOMAIN_SUFFIX"
          ? (candidate.normalizedValue as string).endsWith(rule.pattern as string)
          : rule.ruleType === "IP_RANGE"
            ? (candidate.normalizedValue as string).startsWith((rule.pattern as string).split("/")[0]!.split(".").slice(0, 2).join("."))
            : false;
        if (matches) {
          if (rule.ownershipStatus === "THIRD_PARTY") evidence.push({ kind: "THIRD_PARTY_DECLARATION", reference: rule.id as string, detail: `ownership rule ${rule.ruleType}:${rule.pattern}` });
          else if (rule.ownershipStatus === "SHARED") evidence.push({ kind: "SHARED_INFRASTRUCTURE", reference: rule.id as string, detail: `ownership rule ${rule.ruleType}:${rule.pattern}` });
          else evidence.push({ kind: "REPOSITORY_CONFIGURATION", reference: rule.id as string, detail: `ownership rule ${rule.ruleType}:${rule.pattern}` });
          await this.prisma.easmOwnershipEvidence.create({
            data: { workspaceId, candidateId, kind: "REPOSITORY_CONFIGURATION", reference: rule.id as string, detail: `rule ${rule.ruleType}:${rule.pattern} matched`, createdBy: user.id },
          }).catch(() => undefined);
          const ownerPatch: Row = {};
          if (rule.technicalOwner) ownerPatch.technicalOwner = rule.technicalOwner;
          if (rule.team) ownerPatch.team = rule.team;
          if (rule.application) ownerPatch.application = rule.application;
          if (rule.businessUnit) ownerPatch.businessUnit = rule.businessUnit;
          if (Object.keys(ownerPatch).length > 0) {
            await this.prisma.easmAssetCandidate.update({ where: { id: candidateId }, data: ownerPatch as never });
          }
        }
      }
      const rootRow = candidate.rootAssetId ? roots.find((r) => r.id === candidate.rootAssetId) : null;
      if (rootRow?.authorizationStatus === "VERIFIED") {
        evidence.push({ kind: "MANUAL_APPROVAL", reference: rootRow.id as string, detail: "root asset ownership verified" });
      }
      const resolution = resolveOwnership({ evidence, underRootAsset: !!candidate.rootAssetId });
      if (resolution.status !== candidate.ownershipStatus || resolution.confidence !== candidate.ownershipConfidence) {
        await this.prisma.easmAssetCandidate.update({
          where: { id: candidateId },
          data: { ownershipStatus: resolution.status, ownershipConfidence: resolution.confidence },
        });
        await this.auditSafe({
          actorId: user.id, organizationId: user.organizationId, workspaceId,
          action: "EASM_OWNERSHIP_CHANGED", resourceType: "EasmAssetCandidate", resourceId: candidateId,
          metadata: { from: candidate.ownershipStatus, to: resolution.status, confidence: resolution.confidence, rationale: resolution.rationale },
        });
      }
    }

    // --- Exposure classification (§74) + host snapshots (§40) + signals (§78).
    for (const candidateId of touched) {
      const candidate = (await this.prisma.easmAssetCandidate.findFirst({ where: { id: candidateId, workspaceId } })) as Row | null;
      if (!candidate) continue;
      const identity = candidate.normalizedValue as string;
      const dns = await this.prisma.dnsSnapshot.findFirst({ where: { workspaceId, candidateId }, orderBy: { observedAt: "desc" } });
      const dnsRecords = (dns?.records as unknown as DnsRecord[] | undefined) ?? [];
      const hasPublicDns = dnsRecords.some((r) => (r.type === "A" || r.type === "AAAA") && normalizeIp(r.value) !== null && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(r.value));
      const http = await this.prisma.httpExposureSnapshot.findFirst({ where: { workspaceId, candidateId }, orderBy: { capturedAt: "desc" } });
      const services = (await this.prisma.serviceObservation.findMany({ where: { workspaceId, candidateId } })) as Row[];
      const exposure = classifyInternetExposure({
        dnsPubliclyResolvable: hasPublicDns,
        httpResponded: !!http,
        serviceObserved: services.length > 0,
        checkedAndAbsent: dnsRecords.length > 0 && !hasPublicDns && !http && services.length === 0,
      });
      if (exposure.state !== candidate.exposureState) {
        await this.prisma.easmAssetCandidate.update({ where: { id: candidateId }, data: { exposureState: exposure.state } });
        await this.auditSafe({
          actorId: user.id, organizationId: user.organizationId, workspaceId,
          action: "EASM_EXPOSURE_CHANGED", resourceType: "EasmAssetCandidate", resourceId: candidateId,
          metadata: { from: candidate.exposureState, to: exposure.state, rationale: exposure.rationale },
        });
      }
      const certObs = await this.prisma.easmCertificateObservation.findFirst({ where: { workspaceId, candidateId }, orderBy: { observedAt: "desc" } });
      const cert = certObs ? await this.prisma.easmCertificate.findFirst({ where: { workspaceId, id: certObs.certificateId as string } }) : null;
      const dangling = await this.prisma.danglingDnsCandidate.findFirst({ where: { workspaceId, candidateId, status: "OPEN" } });
      const signals = deriveRiskSignals({
        exposureState: exposure.state, ownershipStatus: candidate.ownershipStatus as string,
        isNew: (Date.now() - new Date(candidate.firstSeen as string).getTime()) < 24 * 3600_000,
        criticality: candidate.criticality as string,
        sensitiveServiceClasses: [...new Set(services.map((s) => s.sensitiveClass).filter(Boolean))] as string[],
        certificateState: cert?.state as string | undefined,
        danglingDnsCandidate: !!dangling,
      });
      await this.prisma.hostExposureSnapshot.create({
        data: {
          workspaceId, programId, candidateId, host: identity,
          resolvedIps: dnsRecords.filter((r) => r.type === "A" || r.type === "AAAA").map((r) => r.value) as never,
          internetVisibility: exposure.state,
          httpState: http ? { status: http.status, title: http.title } as never : {},
          services: services.map((s) => ({ port: s.port, transport: s.transport, service: s.service })) as never,
          technologies: [] as never,
          certificateFingerprint: cert?.fingerprint ?? null,
          riskSignals: signals as never,
        },
      });
      // §89: important signals raise SOC alerts through the governed
      // path — drift never triggers exploitation (§90).
      for (const signal of signals) {
        if (signal === "PUBLIC_SENSITIVE_SERVICE" || signal === "UNKNOWN_PUBLIC_ASSET" || signal === "DANGLING_DNS_CANDIDATE") {
          await this.alerts.raiseAlert({
            organizationId: user.organizationId, workspaceId,
            fingerprint: `easm:${programId}:${identity}:${signal}`,
            title: `EASM ${signal.replace(/_/g, " ")}: ${identity}`,
            description: `EASM signal ${signal} for ${identity} (ownership ${candidate.ownershipStatus}, exposure ${exposure.state}). Signal only — no active testing was performed or authorized by this alert.`,
            severity: signal === "PUBLIC_SENSITIVE_SERVICE" ? "HIGH" : "MEDIUM",
            source: "CORRELATION", actorId: user.id,
          }).catch(() => undefined);
        }
      }
    }

    // --- Service drift events (§45).
    for (const change of serviceChanges) {
      for (const svc of change.added) {
        const sensitive = sensitiveServiceClass({ port: svc.port as number, service: svc.service as string });
        await this.prisma.easmDriftEvent.create({
          data: {
            workspaceId, programId, candidateId: change.candidateId, assetIdentity: change.identity,
            type: "SERVICE_ADDED", after: svc as never,
            severity: sensitive ? "CRITICAL" : "HIGH", status: "OPEN",
            fingerprint: `easm-drift:${change.identity}:SERVICE_ADDED:svc:${svc.port}/${(svc.transport as string) ?? "tcp"}`,
            evidence: { sensitiveServiceClass: sensitive } as never,
          },
        }).catch(() => undefined);
      }
    }
    for (const d of dnsDrift) {
      const candidate = await this.prisma.easmAssetCandidate.findFirst({ where: { id: d.candidateId, workspaceId } });
      await this.prisma.easmDriftEvent.create({
        data: {
          workspaceId, programId, candidateId: d.candidateId, assetIdentity: d.domain,
          type: "DNS_CHANGED", before: { domain: d.domain } as never,
          after: { changes: d.events } as never, severity: "MEDIUM", status: "OPEN",
          fingerprint: `easm-drift:${d.domain}:DNS_CHANGED:${(candidate?.updatedAt as Date)?.toISOString?.() ?? ""}`,
          evidence: { changes: d.events } as never,
        },
      }).catch(() => undefined);
    }

    // --- Snapshot drift vs baseline/last (§80–§85) with flapping (§93).
    const afterSnapshot = await this.buildSnapshot(workspaceId, programId);
    const baseline = await this.prisma.easmBaseline.findFirst({ where: { workspaceId, programId }, orderBy: { version: "desc" } });
    const trustedBefore = baseline ? (baseline.snapshot as unknown as EasmSnapshot) : beforeSnapshot;
    const driftCandidates = compareSnapshots(trustedBefore, afterSnapshot, sensitiveServiceClass);
    let driftRaised = 0;
    for (const drift of driftCandidates) {
      if (drift.type === "SERVICE_ADDED" || drift.type === "CERTIFICATE_CHANGED" || drift.type === "DNS_CHANGED") continue; // already recorded above
      const existing = await this.prisma.easmDriftEvent.findFirst({ where: { workspaceId, fingerprint: drift.fingerprint, status: "PENDING_CONFIRMATION" } });
      const confirmed = !!existing;
      await this.prisma.easmDriftEvent.create({
        data: {
          workspaceId, programId, assetIdentity: drift.assetIdentity, type: drift.type,
          before: drift.before as never, after: drift.after as never, severity: drift.severity,
          fingerprint: drift.fingerprint, status: confirmed ? "OPEN" : "PENDING_CONFIRMATION",
          evidence: { baselineVersion: baseline?.version ?? null } as never,
        },
      }).catch(() => undefined);
      if (confirmed) {
        driftRaised++;
        await this.auditSafe({
          actorId: user.id, organizationId: user.organizationId, workspaceId,
          action: "EASM_DRIFT_DETECTED", resourceType: "EasmAssetCandidate",
          metadata: { programId, type: drift.type, asset: drift.assetIdentity, severity: drift.severity },
        });
        if (drift.severity === "CRITICAL" || drift.severity === "HIGH") {
          await this.alerts.raiseAlert({
            organizationId: user.organizationId, workspaceId,
            fingerprint: drift.fingerprint,
            title: `EASM drift ${drift.type}: ${drift.assetIdentity}`,
            description: `Confirmed drift (${drift.type}) on ${drift.assetIdentity} at severity ${drift.severity}. Review in EASM drift queue; no automated active response is taken.`,
            severity: drift.severity, source: "CORRELATION", actorId: user.id,
          }).catch(() => undefined);
        }
      }
    }

    // --- Disappearance policy (§92) for untouched candidates.
    const allCandidates = (await this.prisma.easmAssetCandidate.findMany({ where: { workspaceId, programId } })) as Row[];
    for (const c of allCandidates) {
      if (touched.has(c.id as string)) continue;
      if (c.lifecycle === "DISAPPEARED" || c.lifecycle === "ARCHIVED") continue;
      const next = nextLifecycleOnObservation({ currentLifecycle: c.lifecycle as string, observedNow: false, missCount: (c.missCount as number) ?? 0, missThreshold: 3 });
      await this.prisma.easmAssetCandidate.update({ where: { id: c.id as string }, data: { lifecycle: next.lifecycle, missCount: next.missCount } });
    }

    // --- Adapter results + run completion (§126–§128).
    for (const row of adapterRows) {
      await this.prisma.easmAdapterRunResult.create({ data: row as never });
    }
    const finalStatus = anyError ? "PARTIAL" : anyNotConfigured ? "PARTIAL" : "COMPLETED";
    const coverage = {
      sourcesSelected: selected, wildcardDomains: [...wildcardDomains],
      droppedActivePayloads: counters.droppedActive, droppedUnapprovedPorts: counters.droppedPort,
      truncatedCandidates: counters.truncated, driftRaised,
      transportConfigured: transportResults.some((t) => t.status !== "NOT_CONFIGURED") || submitted.size > 0,
    };
    const completed = await this.prisma.easmDiscoveryRun.update({
      where: { id: run.id },
      data: {
        status: finalStatus, completedAt: new Date(),
        candidatesFound: counters.found, candidatesNew: counters.created, coverage: coverage as never,
        errors: adapterRows.filter((r) => r.status === "ERROR" || r.status === "NOT_CONFIGURED").map((r) => ({ adapter: r.adapter, status: r.status, errorClass: r.errorClass })) as never,
      },
    });
    await this.auditSafe({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EASM_DISCOVERY_COMPLETED", resourceType: "EasmDiscoveryRun", resourceId: run.id,
      metadata: { programId, status: finalStatus, candidatesFound: counters.found, candidatesNew: counters.created },
    });
    if (counters.created > 0) {
      await this.auditSafe({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "EASM_CANDIDATE_DISCOVERED", resourceType: "EasmProgram", resourceId: programId,
        metadata: { runId: run.id, newCandidates: counters.created },
      });
    }
    return { run: completed, coverage, counters };
  }

  /** Build the current program snapshot (§80) from stored intelligence. */
  async buildSnapshot(workspaceId: string, programId: string): Promise<EasmSnapshot> {
    const candidates = (await this.prisma.easmAssetCandidate.findMany({ where: { workspaceId, programId } })) as Row[];
    const assets = [];
    for (const c of candidates) {
      if (c.lifecycle === "DISAPPEARED" || c.lifecycle === "ARCHIVED") continue;
      const services = (await this.prisma.serviceObservation.findMany({ where: { workspaceId, candidateId: c.id as string } })) as Row[];
      const http = await this.prisma.httpExposureSnapshot.findFirst({ where: { workspaceId, candidateId: c.id as string }, orderBy: { capturedAt: "desc" } });
      const dns = await this.prisma.dnsSnapshot.findFirst({ where: { workspaceId, candidateId: c.id as string }, orderBy: { observedAt: "desc" } });
      const techs = (await this.prisma.technologyObservation.findMany({ where: { workspaceId, candidateId: c.id as string } })) as Row[];
      const certObs = await this.prisma.easmCertificateObservation.findFirst({ where: { workspaceId, candidateId: c.id as string }, orderBy: { observedAt: "desc" } });
      assets.push({
        identity: c.normalizedValue as string,
        services: services.map((s) => ({ port: s.port as number, transport: s.transport as string, service: s.service as string | null })),
        ips: ((dns?.records as unknown as DnsRecord[] | undefined) ?? []).filter((r) => r.type === "A" || r.type === "AAAA").map((r) => r.value),
        httpStatus: (http?.status as number) ?? null,
        httpTitle: (http?.title as string) ?? null,
        certificateFingerprint: (certObs?.certificateId as string) ?? null,
        technologies: techs.map((t) => t.normalizedName as string),
        exposureState: c.exposureState as string,
        ownershipStatus: c.ownershipStatus as string,
      });
    }
    return { capturedAt: new Date().toISOString(), assets };
  }

  async listRuns(user: RequestUser, workspaceId: string, programId: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const items = await this.prisma.easmDiscoveryRun.findMany({ where: { workspaceId, programId }, orderBy: { startedAt: "desc" }, take: 50 });
    const results = await this.prisma.easmAdapterRunResult.findMany({ where: { workspaceId, runId: { in: items.map((i) => i.id) } } });
    return { items, total: items.length, adapterResults: results };
  }
}
