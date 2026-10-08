import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireEasmPermission } from "../permissions";

type Row = Record<string, unknown>;

const AUTHORIZATION_REQUEST = /\b(authorize|approve|scan|attack|exploit|probe|brute|take ?over)\b/i;

/**
 * AI EASM Copilot (Prompt 29 §111–§114, §149). Deterministic,
 * grounded composition over workspace EASM rows — every claim cites
 * the records it came from (§112). Two hard safety rails:
 *  - §113: the copilot may SUGGEST possible ownership; it can never
 *    mark an asset verified-owned (that is the verification workflow).
 *  - §114/§149: it cannot authorize active scanning, and an explicit
 *    request to do so is refused with the workflow explained.
 * There is no execution surface here at all: answers are read-only.
 */
@Injectable()
export class EasmAiService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async ask(user: RequestUser, workspaceId: string, input: { question: string; assetId?: string }) {
    requireEasmPermission(user, "VIEW_EASM");
    const q = input.question.toLowerCase();

    if (AUTHORIZATION_REQUEST.test(input.question) && /(authorize|scan them|scan all|attack|exploit|take ?over)/.test(q)) {
      return {
        answer: "I can't authorize active scanning or testing. Discovered EASM assets stay NOT_AUTHORIZED until a named admin records a separate active-testing authorization for a VERIFIED root asset (AUTHORIZE_EASM_ACTIVE_TESTING), and any scan still requires the platform's target verification + assessment approval gates.",
        citations: [], executed: false as const, refused: "AI_CANNOT_AUTHORIZE" as const,
      };
    }

    const citations: Array<{ type: string; id: string; label: string }> = [];
    const cite = (type: string, row: Row, label: string) => citations.push({ type, id: row.id as string, label });

    if (input.assetId || /why is|risk|changed|this asset/.test(q)) {
      const candidate = input.assetId
        ? await this.prisma.easmAssetCandidate.findFirst({ where: { id: input.assetId, workspaceId } })
        : await this.prisma.easmAssetCandidate.findFirst({ where: { workspaceId }, orderBy: { updatedAt: "desc" } });
      if (!candidate) return { answer: "I don't have a matching EASM asset in this workspace to ground an answer on.", citations, executed: false as const };
      const c = candidate as Row;
      cite("EasmAssetCandidate", c, c.normalizedValue as string);
      const [snapshot, drift, evidence] = await Promise.all([
        this.prisma.hostExposureSnapshot.findFirst({ where: { workspaceId, candidateId: c.id as string }, orderBy: { capturedAt: "desc" } }),
        this.prisma.easmDriftEvent.findMany({ where: { workspaceId, candidateId: c.id as string }, orderBy: { detectedAt: "desc" }, take: 5 }),
        this.prisma.easmOwnershipEvidence.findMany({ where: { workspaceId, candidateId: c.id as string }, take: 5 }),
      ]);
      for (const d of drift as Row[]) cite("EasmDriftEvent", d, `${d.type} (${d.severity})`);
      const signals = (snapshot?.riskSignals as string[] | undefined) ?? [];
      const ownershipNote = c.ownershipStatus === "VERIFIED"
        ? "ownership is VERIFIED through the recorded verification workflow"
        : `ownership is ${c.ownershipStatus} (confidence ${c.ownershipConfidence}) based on ${evidence.length} evidence record(s) — a suggestion from evidence, not a verification`;
      return {
        answer: `${c.normalizedValue}: exposure ${c.exposureState}, ${ownershipNote}, active testing ${c.activeTestingStatus}. Risk signals: ${signals.length ? signals.join(", ") : "none recorded"}. Recent changes: ${drift.length ? (drift as Row[]).map((d) => `${d.type}`).join(", ") : "no drift recorded"}.`,
        citations, executed: false as const,
      };
    }

    if (/certificate|expir/.test(q)) {
      const certs = (await this.prisma.easmCertificate.findMany({ where: { workspaceId }, orderBy: { notAfter: "asc" }, take: 10 })) as Row[];
      const expiring = certs.filter((c) => c.state === "EXPIRING" || c.state === "URGENT" || c.state === "EXPIRED");
      for (const c of expiring) cite("EasmCertificate", c, `${c.subject} (${c.state})`);
      return {
        answer: expiring.length
          ? `${expiring.length} certificate(s) need attention: ${expiring.map((c) => `${c.subject || c.fingerprint} — ${c.state}, expires ${c.notAfter}`).join("; ")}.`
          : "No certificates are recorded as expiring, urgent or expired in this workspace.",
        citations, executed: false as const,
      };
    }

    if (/unknown|unowned|review/.test(q)) {
      const unknown = (await this.prisma.easmAssetCandidate.findMany({
        where: { workspaceId, ownershipStatus: "UNKNOWN" }, orderBy: { firstSeen: "asc" }, take: 10,
      })) as Row[];
      for (const c of unknown) cite("EasmAssetCandidate", c, c.normalizedValue as string);
      return {
        answer: unknown.length
          ? `${unknown.length} asset(s) have UNKNOWN ownership and need review: ${unknown.map((c) => c.normalizedValue).join(", ")}. I can suggest possible ownership from evidence, but only the verification workflow can mark an asset verified-owned.`
          : "No assets with unknown ownership are recorded in this workspace.",
        citations, executed: false as const,
      };
    }

    // Default: "what's new / what changed this week" (§111).
    const weekAgo = new Date(Date.now() - 7 * 86_400_000);
    const [newAssets, drift] = await Promise.all([
      this.prisma.easmAssetCandidate.findMany({ where: { workspaceId, firstSeen: { gte: weekAgo } }, orderBy: { firstSeen: "desc" }, take: 20 }),
      this.prisma.easmDriftEvent.findMany({ where: { workspaceId, detectedAt: { gte: weekAgo } }, orderBy: { detectedAt: "desc" }, take: 20 }),
    ]);
    for (const c of newAssets as Row[]) cite("EasmAssetCandidate", c, c.normalizedValue as string);
    for (const d of drift as Row[]) cite("EasmDriftEvent", d, `${d.type} on ${d.assetIdentity}`);
    if (newAssets.length === 0 && drift.length === 0) {
      return { answer: "INSUFFICIENT_EVIDENCE: no new public assets or drift were recorded in this workspace in the last 7 days.", citations, executed: false as const };
    }
    return {
      answer: `In the last 7 days: ${newAssets.length} new asset(s)${newAssets.length ? ` (${(newAssets as Row[]).map((c) => c.normalizedValue).join(", ")})` : ""}; ${drift.length} drift event(s)${drift.length ? ` (${(drift as Row[]).map((d) => `${d.type} on ${d.assetIdentity}`).join(", ")})` : ""}. All listed assets remain subject to the standard authorization gates before any active testing.`,
      citations, executed: false as const,
    };
  }
}
