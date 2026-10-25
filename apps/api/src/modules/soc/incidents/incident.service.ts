import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { createHash } from "node:crypto";
import { scrubSecretPatterns } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { hasSocPermission, requireSocPermission } from "../permissions";
import { allowedClassifications } from "../../security-analytics/permissions";
import type { Row } from "../helpers";

const INCIDENT_TRANSITIONS: Record<string, string[]> = {
  DRAFT: ["DECLARED", "CLOSED"],
  DECLARED: ["INVESTIGATING", "CLOSED"],
  INVESTIGATING: ["CONTAINING", "CONTAINED", "CLOSED"],
  CONTAINING: ["CONTAINED", "INVESTIGATING"],
  CONTAINED: ["ERADICATING", "MONITORING"],
  ERADICATING: ["RECOVERING", "MONITORING"],
  RECOVERING: ["MONITORING", "CLOSED"],
  MONITORING: ["CLOSED", "INVESTIGATING"],
  CLOSED: [],
};

/**
 * Incidents, cases, timelines, evidence (Prompt 28 §41–§53).
 * Timelines are append-oriented (§46): corrections are amendments,
 * never edits. Evidence is hash-anchored (§49) and access-controlled
 * by incident membership (commander / SOC leads), RBAC permission
 * and classification ceiling (§50); every access — allowed or
 * denied — is written to the chain-of-custody log (§48).
 */
@Injectable()
export class IncidentService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async createIncident(user: RequestUser, workspaceId: string, body: {
    title: string; description?: string; severity: string; priority?: string;
    category?: string; alertIds?: string[]; classification?: string;
  }) {
    requireSocPermission(user, "CREATE_INCIDENTS");
    const incident = await this.prisma.securityIncident.create({
      data: {
        organizationId: user.organizationId, workspaceId, title: body.title,
        description: body.description ?? "", severity: body.severity,
        priority: body.priority ?? "P3", status: "DECLARED", category: body.category ?? "GENERAL",
        classification: body.classification ?? "INTERNAL", declaredAt: new Date(), createdBy: user.id,
      },
    });
    await this.addTimeline(workspaceId, incident.id as string, "SYSTEM", `Incident declared: ${body.title}`, {}, user.id);
    for (const alertId of body.alertIds ?? []) {
      const alert = await this.prisma.securityAlert.findFirst({ where: { id: alertId, workspaceId } });
      if (!alert) continue; // foreign alerts are silently un-linkable — never leaked, never attached (§154)
      await this.linkIncident(workspaceId, incident.id as string, "ALERT", alertId, user.id);
      await this.addTimeline(workspaceId, incident.id as string, "ALERT", `Alert linked: ${(alert as Row).title}`, { alertId }, user.id);
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "INCIDENT_DECLARED", resourceType: "SecurityIncident", resourceId: incident.id as string,
      metadata: { severity: body.severity, priority: body.priority ?? "P3", alerts: (body.alertIds ?? []).length },
    });
    return incident;
  }

  /** §43/§141: escalate an alert to an incident, preserving the
   *  alert relationship (and through it, its matches and events). */
  async escalateAlert(user: RequestUser, workspaceId: string, alertId: string, body: { title?: string }) {
    requireSocPermission(user, "CREATE_INCIDENTS");
    const alert = await this.prisma.securityAlert.findFirst({ where: { id: alertId, workspaceId } });
    if (!alert) throw new NotFoundException("Alert not found in this workspace");
    const incident = await this.createIncident(user, workspaceId, {
      title: body.title ?? `Incident: ${(alert as Row).title}`,
      severity: (alert as Row).severity as string, priority: (alert as Row).priority as string,
      alertIds: [alertId], category: "ALERT_ESCALATION",
    });
    return incident;
  }

  async listIncidents(user: RequestUser, workspaceId: string, filters: { status?: string; priority?: string; limit?: number }) {
    requireSocPermission(user, "VIEW_INCIDENTS");
    const items = await this.prisma.securityIncident.findMany({
      where: {
        workspaceId,
        ...(filters.status ? { status: filters.status } : {}),
        ...(filters.priority ? { priority: filters.priority } : {}),
      },
      orderBy: { detectedAt: "desc" }, take: Math.min(filters.limit ?? 100, 500),
    });
    return { items, total: items.length };
  }

  async getIncident(user: RequestUser, workspaceId: string, incidentId: string): Promise<Row> {
    requireSocPermission(user, "VIEW_INCIDENTS");
    const incident = await this.prisma.securityIncident.findFirst({ where: { id: incidentId, workspaceId } });
    if (!incident) throw new NotFoundException("Incident not found in this workspace");
    return incident as Row;
  }

  async getIncidentDetail(user: RequestUser, workspaceId: string, incidentId: string) {
    const incident = await this.getIncident(user, workspaceId, incidentId);
    const [links, timeline, evidence, communications, playbookRuns, responseActions, pir] = await Promise.all([
      this.prisma.incidentLink.findMany({ where: { workspaceId, incidentId } }),
      this.prisma.incidentTimelineEntry.findMany({ where: { workspaceId, incidentId }, orderBy: { createdAt: "asc" }, take: 500 }),
      this.prisma.incidentEvidence.findMany({ where: { workspaceId, incidentId }, orderBy: { collectedAt: "desc" } }),
      this.prisma.incidentCommunication.findMany({ where: { workspaceId, incidentId }, orderBy: { createdAt: "desc" } }),
      this.prisma.incidentPlaybookRun.findMany({ where: { workspaceId, incidentId }, orderBy: { startedAt: "desc" } }),
      this.prisma.responseActionExecution.findMany({ where: { workspaceId, incidentId }, orderBy: { createdAt: "desc" } }),
      this.prisma.postIncidentReview.findFirst({ where: { incidentId } }),
    ]);
    return { incident, links, timeline, evidence, communications, playbookRuns, responseActions, postIncidentReview: pir };
  }

  async patchIncident(user: RequestUser, workspaceId: string, incidentId: string, body: {
    status?: string; commanderId?: string; businessImpact?: string; severity?: string; priority?: string;
  }) {
    requireSocPermission(user, "MANAGE_INCIDENTS");
    const incident = await this.getIncident(user, workspaceId, incidentId);
    const data: Row = {};
    if (body.status !== undefined) {
      const allowed = INCIDENT_TRANSITIONS[incident.status as string] ?? [];
      if (!allowed.includes(body.status)) {
        throw new BadRequestException(`Incident cannot move from ${incident.status} to ${body.status}`);
      }
      data.status = body.status;
      if (body.status === "CONTAINED" && !incident.containedAt) data.containedAt = new Date();
      if (body.status === "RECOVERING" && !incident.recoveredAt) data.recoveredAt = new Date();
      if (body.status === "CLOSED") data.closedAt = new Date();
    }
    if (body.commanderId !== undefined) data.commanderId = body.commanderId;
    if (body.businessImpact !== undefined) data.businessImpact = body.businessImpact;
    if (body.severity !== undefined) data.severity = body.severity;
    if (body.priority !== undefined) data.priority = body.priority;
    const updated = await this.prisma.securityIncident.update({ where: { id: incidentId }, data: data as never });
    if (body.status !== undefined) {
      await this.addTimeline(workspaceId, incidentId, "STATUS_CHANGE", `Status changed: ${incident.status} → ${body.status}`, { from: incident.status, to: body.status }, user.id);
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "INCIDENT_STATUS_CHANGED", resourceType: "SecurityIncident", resourceId: incidentId,
        metadata: { from: incident.status, to: body.status },
      });
    }
    return updated;
  }

  async linkIncident(workspaceId: string, incidentId: string, resourceType: string, resourceId: string, actorId?: string) {
    const existing = await this.prisma.incidentLink.findFirst({ where: { incidentId, resourceType, resourceId } });
    if (existing) return existing;
    return this.prisma.incidentLink.create({
      data: { incidentId, workspaceId, resourceType, resourceId, createdBy: actorId },
    });
  }

  async addTimeline(workspaceId: string, incidentId: string, entryType: string, summary: string, detail: Row, actorId?: string, amendsEntryId?: string) {
    return this.prisma.incidentTimelineEntry.create({
      data: {
        incidentId, workspaceId, entryType,
        summary: scrubSecretPatterns(summary).text,
        detail: detail as never, actorId, amendsEntryId,
      },
    });
  }

  async addTimelineEntry(user: RequestUser, workspaceId: string, incidentId: string, body: {
    entryType?: string; summary: string; amendsEntryId?: string;
  }) {
    // Analyst timeline notes are staff work; lifecycle/management
    // actions remain LEADS-gated elsewhere.
    requireSocPermission(user, "TRIAGE_ALERTS");
    await this.getIncident(user, workspaceId, incidentId);
    if (body.amendsEntryId) {
      const target = await this.prisma.incidentTimelineEntry.findFirst({ where: { id: body.amendsEntryId, incidentId, workspaceId } });
      if (!target) throw new NotFoundException("Timeline entry to amend not found (§46: amendments reference existing entries)");
    }
    return this.addTimeline(workspaceId, incidentId, body.entryType || "ANALYST_NOTE", body.summary, {}, user.id, body.amendsEntryId);
  }

  /** §50: evidence access gate — incident membership (commander or
   *  creator), the evidence permission, and the classification
   *  ceiling must ALL hold. */
  private async assertEvidenceAccess(user: RequestUser, incident: Row, evidence: Row, action: string): Promise<void> {
    const allowed = allowedClassifications(user);
    const member = incident.commanderId === user.id || incident.createdBy === user.id || hasSocPermission(user, "MANAGE_INCIDENT_EVIDENCE");
    const ok = hasSocPermission(user, "VIEW_INCIDENT_EVIDENCE") && member && allowed.includes(evidence.classification as string);
    await this.prisma.incidentEvidenceAccess.create({
      data: {
        evidenceId: evidence.id as string, incidentId: incident.id as string, workspaceId: incident.workspaceId as string,
        actorId: user.id, action, result: ok ? "ALLOWED" : "DENIED",
      },
    }).catch(() => undefined);
    if (!ok) throw new ForbiddenException("Evidence access denied: membership, permission or classification ceiling not satisfied (§50)");
  }

  async addEvidence(user: RequestUser, workspaceId: string, incidentId: string, body: {
    source: string; classification?: string; objectReference: string; description?: string;
    content: string; relatedEventId?: string; relatedAssetId?: string;
  }) {
    requireSocPermission(user, "MANAGE_INCIDENT_EVIDENCE");
    const incident = await this.getIncident(user, workspaceId, incidentId);
    void incident;
    const contentHash = createHash("sha256").update(body.content).digest("hex");
    // §143: telemetry evidence is verified against the stored
    // event's integrity hash at collection time.
    let verified: boolean | null = null;
    if (body.source === "TELEMETRY_EVENT" && body.relatedEventId) {
      const event = await this.prisma.securityTelemetryEvent.findFirst({ where: { id: body.relatedEventId, workspaceId } });
      if (!event) throw new NotFoundException("Related telemetry event not found in this workspace");
      verified = (event as Row).contentHash === contentHash;
      if (!verified) throw new BadRequestException("Evidence content hash does not match the stored telemetry event — tampered or wrong content (§143)");
    }
    const evidence = await this.prisma.incidentEvidence.create({
      data: {
        incidentId, workspaceId, source: body.source,
        classification: body.classification ?? "CONFIDENTIAL",
        contentHash, objectReference: body.objectReference, description: body.description ?? "",
        relatedEventId: body.relatedEventId, relatedAssetId: body.relatedAssetId,
        collectedBy: user.id,
        chainMetadata: { verifiedAtCollection: verified, collector: user.id } as never,
      },
    });
    await this.addTimeline(workspaceId, incidentId, "EVIDENCE", `Evidence added: ${body.description || body.objectReference} (sha256 ${contentHash.slice(0, 12)}…)`, { evidenceId: evidence.id }, user.id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "INCIDENT_EVIDENCE_ADDED", resourceType: "IncidentEvidence", resourceId: evidence.id as string,
      metadata: { incidentId, source: body.source, verified },
    });
    return evidence;
  }

  /** §49: verify stored evidence integrity + record the access. */
  async verifyEvidence(user: RequestUser, workspaceId: string, incidentId: string, evidenceId: string, content: string) {
    const incident = await this.getIncident(user, workspaceId, incidentId);
    const evidence = await this.prisma.incidentEvidence.findFirst({ where: { id: evidenceId, incidentId, workspaceId } });
    if (!evidence) throw new NotFoundException("Evidence not found on this incident");
    await this.assertEvidenceAccess(user, incident, evidence as Row, "VERIFIED");
    const hash = createHash("sha256").update(content).digest("hex");
    return { evidenceId, storedHash: (evidence as Row).contentHash, computedHash: hash, integrityOk: hash === (evidence as Row).contentHash };
  }

  async getEvidence(user: RequestUser, workspaceId: string, incidentId: string, evidenceId: string) {
    const incident = await this.getIncident(user, workspaceId, incidentId);
    const evidence = await this.prisma.incidentEvidence.findFirst({ where: { id: evidenceId, incidentId, workspaceId } });
    if (!evidence) throw new NotFoundException("Evidence not found on this incident");
    await this.assertEvidenceAccess(user, incident, evidence as Row, "VIEWED");
    const accesses = await this.prisma.incidentEvidenceAccess.findMany({
      where: { workspaceId, evidenceId }, orderBy: { createdAt: "asc" },
    });
    return { evidence, accessHistory: accesses };
  }

  /* ------------------------------ cases (§51–§53) ------------------------------ */

  async createCase(user: RequestUser, workspaceId: string, body: {
    title: string; description?: string; severity?: string; linkedAlertIds?: string[]; linkedEventIds?: string[];
  }) {
    requireSocPermission(user, "CREATE_INCIDENTS");
    const kase = await this.prisma.investigationCase.create({
      data: {
        organizationId: user.organizationId, workspaceId, title: body.title,
        description: body.description ?? "", severity: body.severity ?? "MEDIUM",
        linkedAlertIds: (body.linkedAlertIds ?? []) as never, linkedEventIds: (body.linkedEventIds ?? []) as never,
        createdBy: user.id,
      },
    });
    return kase;
  }

  async listCases(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_INCIDENTS");
    const items = await this.prisma.investigationCase.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
    return { items, total: items.length };
  }

  /** §53: case → incident escalation preserving references. */
  async escalateCase(user: RequestUser, workspaceId: string, caseId: string) {
    requireSocPermission(user, "CREATE_INCIDENTS");
    const kase = await this.prisma.investigationCase.findFirst({ where: { id: caseId, workspaceId } });
    if (!kase) throw new NotFoundException("Case not found in this workspace");
    if ((kase as Row).escalatedIncidentId) throw new BadRequestException("Case already escalated");
    const incident = await this.createIncident(user, workspaceId, {
      title: (kase as Row).title as string, description: (kase as Row).description as string,
      severity: (kase as Row).severity as string, alertIds: ((kase as Row).linkedAlertIds as string[]) ?? [],
      category: "CASE_ESCALATION",
    });
    await this.prisma.securityIncident.update({ where: { id: incident.id as string }, data: { caseId } as never });
    for (const eventId of ((kase as Row).linkedEventIds as string[]) ?? []) {
      await this.linkIncident(workspaceId, incident.id as string, "EVENT", eventId, user.id);
    }
    const updatedCase = await this.prisma.investigationCase.update({
      where: { id: caseId }, data: { status: "ESCALATED", escalatedIncidentId: incident.id as string } as never,
    });
    return { case: updatedCase, incident };
  }

  /* --------------------------- communications (§93) --------------------------- */

  async addCommunication(user: RequestUser, workspaceId: string, incidentId: string, body: {
    audience: string; channel: string; template?: string; message: string;
  }) {
    requireSocPermission(user, "MANAGE_INCIDENTS");
    await this.getIncident(user, workspaceId, incidentId);
    const comm = await this.prisma.incidentCommunication.create({
      data: {
        incidentId, workspaceId, audience: body.audience, channel: body.channel,
        template: body.template, messageSnapshot: scrubSecretPatterns(body.message).text,
        authorId: user.id, deliveryStatus: body.channel === "IN_APP" ? "RECORDED" : "QUEUED",
      },
    });
    await this.addTimeline(workspaceId, incidentId, "COMMUNICATION", `${body.audience} update via ${body.channel}`, { communicationId: comm.id }, user.id);
    return comm;
  }

  /* ------------------------------ PIR (§118) ------------------------------ */

  async upsertPir(user: RequestUser, workspaceId: string, incidentId: string, body: Row) {
    requireSocPermission(user, "MANAGE_INCIDENTS");
    await this.getIncident(user, workspaceId, incidentId);
    const existing = await this.prisma.postIncidentReview.findFirst({ where: { incidentId } });
    const data: Row = {
      summary: body.summary ?? "", impact: body.impact ?? "", rootCause: body.rootCause ?? "",
      rootCauseState: body.rootCauseState ?? "UNKNOWN",
      detectionGaps: body.detectionGaps ?? [], responseGaps: body.responseGaps ?? [],
      lessons: body.lessons ?? [], followUpActions: body.followUpActions ?? [],
      ownerId: body.ownerId ?? user.id, status: body.status ?? "DRAFT",
      completedAt: body.status === "COMPLETED" ? new Date() : undefined,
    };
    const pir = existing
      ? await this.prisma.postIncidentReview.update({ where: { id: (existing as Row).id as string }, data: data as never })
      : await this.prisma.postIncidentReview.create({ data: { incidentId, workspaceId, ...data } as never });
    if (body.status === "COMPLETED") {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "POST_INCIDENT_REVIEW_COMPLETED", resourceType: "PostIncidentReview",
        resourceId: (pir as Row).id as string, metadata: { incidentId, rootCauseState: data.rootCauseState },
      });
    }
    return pir;
  }

  /* --------------------------- reports (§117) --------------------------- */

  /** Incident reports are composed ONLY from the incident's own
   *  records and pass the platform redaction scrubber; the content
   *  is hash-anchored like every other platform snapshot. */
  async generateReport(user: RequestUser, workspaceId: string, incidentId: string, type: string) {
    requireSocPermission(user, "GENERATE_INCIDENT_REPORT");
    const detail = await this.getIncidentDetail(user, workspaceId, incidentId);
    const incident = detail.incident as Row;
    const content: Row = {
      type,
      incident: {
        id: incident.id, title: incident.title, status: incident.status,
        severity: incident.severity, priority: incident.priority,
        detectedAt: incident.detectedAt, containedAt: incident.containedAt, closedAt: incident.closedAt,
      },
      alerts: (detail.links as Row[]).filter((l) => l.resourceType === "ALERT").map((l) => l.resourceId),
      timeline: (detail.timeline as Row[]).map((t) => ({ at: t.createdAt, type: t.entryType, summary: t.summary })),
      evidence: (detail.evidence as Row[]).map((e) => ({ id: e.id, source: e.source, hash: e.contentHash, classification: e.classification })),
      responseActions: (detail.responseActions as Row[]).map((a) => ({ actionKey: a.actionKey, status: a.status })),
      postIncidentReview: detail.postIncidentReview
        ? { rootCauseState: (detail.postIncidentReview as Row).rootCauseState, status: (detail.postIncidentReview as Row).status }
        : null,
      note: type === "EXECUTIVE_SUMMARY"
        ? "Executive summary — derived from the incident record only; no attribution is made (§99)."
        : "Derived from the incident record only; evidence content is referenced by hash, never embedded.",
    };
    const serialized = JSON.stringify(content);
    const report = await this.prisma.socIncidentReport.create({
      data: {
        incidentId, workspaceId, type, content: content as never,
        contentHash: createHash("sha256").update(serialized).digest("hex"), generatedBy: user.id,
      },
    });
    await this.addTimeline(workspaceId, incidentId, "SYSTEM", `Report generated: ${type}`, { reportId: report.id }, user.id);
    return report;
  }

  /** §73: read-only incident relationship graph. */
  async incidentGraph(user: RequestUser, workspaceId: string, incidentId: string) {
    const detail = await this.getIncidentDetail(user, workspaceId, incidentId);
    const nodes: Array<{ id: string; kind: string; label: string }> = [
      { id: incidentId, kind: "INCIDENT", label: (detail.incident as Row).title as string },
    ];
    const edges: Array<{ from: string; to: string; kind: string }> = [];
    for (const link of detail.links as Row[]) {
      nodes.push({ id: link.resourceId as string, kind: link.resourceType as string, label: link.resourceId as string });
      edges.push({ from: incidentId, to: link.resourceId as string, kind: link.resourceType as string });
    }
    return { nodes, edges, readOnly: true };
  }
}
