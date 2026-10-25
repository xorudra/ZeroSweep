import { Body, Controller, Delete, Get, NotFoundException, Param, Patch, Post, Query, Inject } from "@nestjs/common";
import {
  createAuthenticationProfileSchema, createSessionProfileSchema, createScannerInstanceSchema,
  grantScanApprovalSchema, scannerImportSchema, updateScannerInstanceSchema,
} from "@zerosweep/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { ScannersService } from "./scanners.service";

/**
 * Scanner administration (Prompt 8 §54–§56): instances, session profiles,
 * active-scan approvals and manual imports. OWNER/ADMIN operate the
 * registry; SECURITY_ENGINEER may import exports and read profiles.
 * Responses contain metadata + reference NAMES only — a secret value can
 * never appear here because none is ever accepted or stored (§20).
 */
@Controller("scanners")
export class ScannersController {
  constructor(
    private readonly scanners: ScannersService,
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
  ) {}

  // ------------------------------ instances ------------------------------
  @Get("instances")
  listInstances(@CurrentUser() user: RequestUser) {
    return this.scanners.listInstances(user);
  }

  @Post("instances")
  createInstance(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createScannerInstanceSchema, body);
    return this.scanners.createInstance(user, { ...data, deploymentType: data.deploymentType ?? "MANAGED_DAEMON" });
  }

  @Patch("instances/:id")
  updateInstance(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const data = parseOrThrow(updateScannerInstanceSchema, body);
    return this.scanners.updateInstance(user, id, data);
  }

  @Delete("instances/:id")
  deleteInstance(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.scanners.deleteInstance(user, id);
  }

  @Post("instances/:id/health-check")
  healthCheck(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.scanners.healthCheckInstance(user, id);
  }

  // --------------------------- session profiles ---------------------------
  @Get("session-profiles")
  async listSessionProfiles(@CurrentUser() user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.sessionProfile.findMany({
      where: { workspaceId: workspace.id },
      include: { authProfiles: true },
      orderBy: { createdAt: "desc" },
    });
  }

  @Post("session-profiles")
  async createSessionProfile(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createSessionProfileSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.sessionProfile.create({
      data: {
        workspaceId: workspace.id, name: data.name, type: data.type as never,
        credentialReference: data.credentialReference ?? null,
        cookiePolicy: (data.cookiePolicy ?? undefined) as never,
        headerPolicy: (data.headerPolicy ?? undefined) as never,
        validation: (data.validation ?? undefined) as never,
        createdBy: user.id,
      },
    });
  }

  @Post("session-profiles/:id/authentication-profiles")
  async createAuthenticationProfile(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const data = parseOrThrow(createAuthenticationProfileSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    const profile = await this.prisma.sessionProfile.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!profile) throw new NotFoundException("Session profile not found");
    return this.prisma.authenticationProfile.create({
      data: {
        sessionProfileId: id, mode: data.mode as never,
        loginUrl: data.loginUrl ?? null, usernameField: data.usernameField ?? null,
        passwordField: data.passwordField ?? null, tokenHeaderName: data.tokenHeaderName ?? null,
        credentialReference: data.credentialReference ?? null,
        config: (data.config ?? undefined) as never,
      },
    });
  }

  // ------------------------------ approvals ------------------------------
  @Get("approvals")
  listApprovals(@CurrentUser() user: RequestUser, @Query("assessmentId") assessmentId?: string) {
    return this.scanners.listApprovals(user, assessmentId);
  }

  @Post("approvals")
  grantApproval(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(grantScanApprovalSchema, body);
    return this.scanners.grantApproval(user, { ...data, capability: data.capability ?? "ACTIVE_WEB_SCANNING" });
  }

  @Post("approvals/:id/revoke")
  revokeApproval(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.scanners.revokeApproval(user, id);
  }

  // ------------------------------- imports -------------------------------
  @Post("import")
  importExport(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(scannerImportSchema, body);
    return this.scanners.importExport(user, data);
  }
}

/**
 * Scan HTTP history (Prompt 8 §59/§60): the scan-level view over
 * proxy-observed transactions. List + detail expose metadata and REDACTED
 * display copies only. The raw-evidence endpoint is OWNER/ADMIN, always
 * audited (RAW_EVIDENCE_ACCESSED), and returns artifact references +
 * integrity hashes — raw bodies live in worker object storage, and this
 * access record is the control that governs them.
 */
@Controller("scans")
export class ScanHttpHistoryController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private async resolveScan(user: RequestUser, scanId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    return { workspace, scan };
  }

  @Get(":id/http-history")
  async list(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("host") host?: string, @Query("source") source?: string) {
    const { workspace } = await this.resolveScan(user, id);
    const rows = await this.prisma.httpTransaction.findMany({
      where: { scanId: id, workspaceId: workspace.id, ...(host ? { host } : {}), ...(source ? { source } : {}) },
      select: {
        id: true, method: true, url: true, host: true, statusCode: true, source: true,
        scopeStatus: true, apiKind: true, requestHash: true, responseHash: true,
        requestSize: true, responseSize: true, observedAt: true,
      },
      orderBy: { observedAt: "desc" },
      take: 500,
    });
    const webSockets = await this.prisma.webSocketEndpoint.findMany({
      where: { scanId: id, workspaceId: workspace.id },
      orderBy: { createdAt: "asc" },
    });
    return { transactions: rows, webSockets };
  }

  @Get(":id/http-history/:txId")
  async detail(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("txId") txId: string) {
    const { workspace } = await this.resolveScan(user, id);
    const tx = await this.prisma.httpTransaction.findFirst({ where: { id: txId, scanId: id, workspaceId: workspace.id } });
    if (!tx) throw new NotFoundException("Transaction not found");
    return tx;
  }

  @Get(":id/http-history/:txId/raw")
  async raw(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("txId") txId: string) {
    const { workspace } = await this.resolveScan(user, id);
    const tx = await this.prisma.httpTransaction.findFirst({ where: { id: txId, scanId: id, workspaceId: workspace.id } });
    if (!tx) throw new NotFoundException("Transaction not found");
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "RAW_EVIDENCE_ACCESSED", resourceType: "HttpTransaction", resourceId: tx.id,
      metadata: { scanId: id, requestHash: tx.requestHash ?? null, responseHash: tx.responseHash ?? null },
    });
    return {
      transactionId: tx.id,
      requestArtifactRef: tx.requestArtifactRef,
      responseArtifactRef: tx.responseArtifactRef,
      requestHash: tx.requestHash,
      responseHash: tx.responseHash,
      requestRedacted: tx.requestRedacted,
      responseRedacted: tx.responseRedacted,
      note: "Raw request/response bytes live in worker object storage under the artifact reference; this audited endpoint returns the references, integrity hashes and the redacted display copies (§26/§60).",
    };
  }
}
