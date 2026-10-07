import { BadRequestException, Body, Controller, Get, Inject, NotFoundException, Param, Patch, Post, Query } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
const STATUSES = ["OPEN", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"];
const VERIFICATION = ["UNVERIFIED", "LIKELY", "CONFIRMED", "REJECTED"];

/** Status transitions a reviewer may drive (§32): a finding's review is
 *  explicit, reasoned and audited — never a silent database edit. */
const TRANSITIONS: Record<string, string[]> = {
  OPEN: ["CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"],
  CONFIRMED: ["FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED", "OPEN"],
  FALSE_POSITIVE: ["OPEN"],
  ACCEPTED_RISK: ["OPEN", "RESOLVED"],
  RESOLVED: ["OPEN"], // reopen on retest failure (§37)
};
const STATUS_AUDIT: Record<string, string> = {
  CONFIRMED: "FINDING_CONFIRMED", FALSE_POSITIVE: "FINDING_FALSE_POSITIVE",
};
const STATUS_HISTORY: Record<string, string> = {
  CONFIRMED: "CONFIRMED", FALSE_POSITIVE: "FALSE_POSITIVE",
  ACCEPTED_RISK: "ACCEPTED_RISK", RESOLVED: "RESOLVED", OPEN: "REOPENED",
};

function parseBool(v: string | undefined): boolean | undefined {
  if (v === undefined) return undefined;
  if (v === "true") return true;
  if (v === "false") return false;
  throw new BadRequestException("boolean filter must be true or false");
}

/**
 * Findings API (Prompt 7 §38/§39): filtered listing, full detail with
 * evidence + references + review history, and the manual validation
 * workflow (confirm / false-positive / accept-risk / resolve / reopen)
 * with reviewer identity, timestamps, reasons and audit events (§32/§33/
 * §66). Everything is workspace-scoped; evidence is stored REDACTED at
 * ingestion (§30) and served as inert text (§55).
 */
@Controller("findings")
export class FindingsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  @Get()
  async list(
    @CurrentUser() user: RequestUser,
    @Query("severity") severity?: string,
    @Query("status") status?: string,
    @Query("confidence") confidenceBand?: string,
    @Query("verificationStatus") verificationStatus?: string,
    @Query("tool") tool?: string,
    @Query("assetId") assetId?: string,
    @Query("host") host?: string,
    @Query("cve") cve?: string,
    @Query("cwe") cwe?: string,
    @Query("owasp") owasp?: string,
    @Query("scanId") scanId?: string,
    @Query("from") from?: string,
    @Query("to") to?: string,
    @Query("duplicates") duplicates?: string,
    @Query("page") page = "1",
    @Query("pageSize") pageSize = "50",
  ) {
    const ws = await resolveWorkspace(this.prisma, user);
    if (severity && !SEVERITIES.includes(severity)) throw new BadRequestException(`severity must be one of ${SEVERITIES.join(", ")}`);
    if (status && !STATUSES.includes(status)) throw new BadRequestException(`status must be one of ${STATUSES.join(", ")}`);
    if (verificationStatus && !VERIFICATION.includes(verificationStatus)) throw new BadRequestException(`verificationStatus must be one of ${VERIFICATION.join(", ")}`);
    const where: Record<string, unknown> = { workspaceId: ws.id };
    if (severity) where.severity = severity;
    if (status) where.status = status;
    if (confidenceBand) where.confidenceBand = confidenceBand;
    if (verificationStatus) where.verificationStatus = verificationStatus;
    if (tool) where.sources = { has: tool };
    if (assetId) where.assetId = assetId;
    if (host) where.host = host;
    if (cve) where.cve = cve.toUpperCase();
    if (cwe) where.cwe = cwe.toUpperCase().startsWith("CWE-") ? cwe.toUpperCase() : `CWE-${cwe}`;
    if (owasp) where.owaspCategory = { contains: owasp };
    if (scanId) where.scanId = scanId;
    const createdAt: Record<string, Date> = {};
    if (from) { const d = new Date(from); if (Number.isNaN(d.getTime())) throw new BadRequestException("from must be an ISO date"); createdAt.gte = d; }
    if (to) { const d = new Date(to); if (Number.isNaN(d.getTime())) throw new BadRequestException("to must be an ISO date"); createdAt.lte = d; }
    if (Object.keys(createdAt).length > 0) where.createdAt = createdAt;
    // Duplicates (merged rows) are hidden from the default listing; the
    // canonical finding carries their evidence (§20/§39).
    const showDuplicates = parseBool(duplicates);
    if (!showDuplicates) where.duplicateOfId = null;
    const p = Math.max(1, Number(page) || 1);
    const size = Math.min(200, Math.max(1, Number(pageSize) || 50));
    const [total, items] = await Promise.all([
      this.prisma.finding.count({ where }),
      this.prisma.finding.findMany({
        where, orderBy: [{ riskScore: "desc" }, { createdAt: "desc" }],
        skip: (p - 1) * size, take: size,
        include: { _count: { select: { evidence: true } } },
      }),
    ]);
    return {
      items: items.map((f) => ({
        ...f,
        sourceCount: f.sources?.length ?? 0,
        evidenceCount: f._count?.evidence ?? 0,
        _count: undefined,
      })),
      total, page: p, pageSize: size,
    };
  }

  /** Severity counts + top vulnerabilities for the overview (§44) —
   *  computed from REAL persisted findings; zero findings = honest zeros. */
  @Get("summary")
  async summary(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    const where = { workspaceId: ws.id, duplicateOfId: null };
    const [bySeverity, byVerification, total, top] = await Promise.all([
      this.prisma.finding.groupBy({ by: ["severity"], where, _count: true }),
      this.prisma.finding.groupBy({ by: ["verificationStatus"], where, _count: true }),
      this.prisma.finding.count({ where }),
      this.prisma.finding.findMany({
        where, orderBy: [{ riskScore: "desc" }], take: 10,
        select: { id: true, title: true, severity: true, riskScore: true, host: true, sources: true, status: true },
      }),
    ]);
    const counts = (rows: unknown, key: string) =>
      Object.fromEntries((rows as Record<string, unknown>[]).map((r) => [r[key] as string, r._count as number]));
    return {
      total,
      bySeverity: counts(bySeverity, "severity"),
      byVerificationStatus: counts(byVerification, "verificationStatus"),
      topVulnerabilities: top,
    };
  }

  private async load(user: RequestUser, id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    const finding = await this.prisma.finding.findFirst({ where: { id, workspaceId: ws.id } });
    if (!finding) throw new NotFoundException("Finding not found");
    return { ws, finding };
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const { finding } = await this.load(user, id);
    const [evidence, references, history, duplicates] = await Promise.all([
      this.prisma.findingEvidence.findMany({ where: { findingId: id }, orderBy: { createdAt: "asc" } }),
      this.prisma.findingReference.findMany({ where: { findingId: id } }),
      this.prisma.findingHistory.findMany({ where: { findingId: id }, orderBy: { createdAt: "asc" } }),
      this.prisma.finding.findMany({ where: { duplicateOfId: id }, select: { id: true, title: true, severity: true } }),
    ]);
    return { ...finding, evidence, references, history, duplicates };
  }

  /** Sanitized evidence view (§29/§55): evidence was redacted at ingestion;
   *  the API returns text + metadata only — never raw artifact downloads. */
  @Get(":id/evidence")
  async evidence(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    await this.load(user, id);
    const rows = await this.prisma.findingEvidence.findMany({ where: { findingId: id }, orderBy: { createdAt: "asc" } });
    return {
      findingId: id,
      evidence: rows.map((e) => ({
        id: e.id, sourceTool: e.sourceTool, evidenceType: e.evidenceType,
        summary: e.summary, matchedAt: e.matchedAt, fingerprint: e.fingerprint, metadata: e.metadata,
      })),
    };
  }

  @Patch(":id/status")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST")
  async updateStatus(
    @CurrentUser() user: RequestUser, @Param("id") id: string,
    @Body() body: { status?: string; verificationStatus?: string; reason?: string },
  ) {
    const { ws, finding } = await this.load(user, id);
    const patch: Record<string, unknown> = {};
    if (body.verificationStatus !== undefined) {
      if (!VERIFICATION.includes(body.verificationStatus)) throw new BadRequestException(`verificationStatus must be one of ${VERIFICATION.join(", ")}`);
      patch.verificationStatus = body.verificationStatus;
    }
    if (body.status !== undefined) {
      if (!STATUSES.includes(body.status)) throw new BadRequestException(`status must be one of ${STATUSES.join(", ")}`);
      const allowed = TRANSITIONS[finding.status] ?? [];
      if (body.status !== finding.status && !allowed.includes(body.status)) {
        throw new BadRequestException(`Cannot move a ${finding.status} finding to ${body.status}`);
      }
      if (body.status !== finding.status && !body.reason?.trim()) {
        throw new BadRequestException("A reason is required when changing a finding's status (§32)");
      }
      patch.status = body.status;
    }
    if (Object.keys(patch).length === 0) throw new BadRequestException("Nothing to update: provide status and/or verificationStatus");
    const updated = await this.prisma.finding.update({ where: { id }, data: patch });
    if (body.status && body.status !== finding.status) {
      await this.prisma.findingHistory.create({
        data: { findingId: id, workspaceId: ws.id, event: STATUS_HISTORY[body.status] ?? "REVIEWED", actorId: user.id, notes: body.reason },
      });
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId: ws.id,
        action: STATUS_AUDIT[body.status] ?? "FINDING_REVIEWED", resourceType: "Finding", resourceId: id,
        metadata: { status: body.status, reason: body.reason },
      });
    }
    return updated;
  }

  /** Review workflow (§32/§33): reviewer + timestamp + notes are recorded
   *  on the finding AND as an immutable history event + audit row. The
   *  scanner's original evidence is never modified by a review. */
  @Post(":id/review")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST")
  async review(
    @CurrentUser() user: RequestUser, @Param("id") id: string,
    @Body() body: { status?: string; notes?: string },
  ) {
    const { ws, finding } = await this.load(user, id);
    if (!body.status || !STATUSES.includes(body.status)) throw new BadRequestException(`status must be one of ${STATUSES.join(", ")}`);
    if (!body.notes?.trim()) throw new BadRequestException("Review notes are required — a review without a reason is not a review (§32)");
    const allowed = TRANSITIONS[finding.status] ?? [];
    if (body.status !== finding.status && !allowed.includes(body.status)) {
      throw new BadRequestException(`Cannot move a ${finding.status} finding to ${body.status}`);
    }
    const updated = await this.prisma.finding.update({
      where: { id },
      data: {
        status: body.status as never, reviewStatus: body.status, reviewedBy: user.id,
        reviewedAt: new Date(), reviewNotes: body.notes,
        ...(body.status === "CONFIRMED" ? { verificationStatus: "CONFIRMED" } : {}),
        ...(body.status === "FALSE_POSITIVE" ? { verificationStatus: "REJECTED" } : {}),
      },
    });
    await this.prisma.findingHistory.create({
      data: { findingId: id, workspaceId: ws.id, event: STATUS_HISTORY[body.status] ?? "REVIEWED", actorId: user.id, notes: body.notes },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: ws.id,
      action: STATUS_AUDIT[body.status] ?? "FINDING_REVIEWED", resourceType: "Finding", resourceId: id,
      metadata: { status: body.status, notes: body.notes, reviewer: user.id },
    });
    return updated;
  }
}
