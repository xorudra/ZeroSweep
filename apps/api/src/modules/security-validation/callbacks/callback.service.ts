import { BadRequestException, HttpException, Inject, Injectable } from "@nestjs/common";
import {
  hashCallbackToken,
  issueCallbackToken,
  verifyCallbackToken,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireValidationPermission } from "../permissions";
import { ValidationPoliciesService } from "../policies/policies.service";

/**
 * Controlled callback service (Prompt 16 §47–§50). Tokens are unique,
 * random, short-lived, tenant- and session-bound; only the HASH is
 * stored. A token is NOT authorization (§48): ingestion records
 * minimal metadata (kind, source IP, timestamp) and returns nothing
 * about the tenant. Ingestion is rate-limited per token and per IP.
 * DNS callbacks (§49) use the same token discipline on ZeroSweep-owned
 * validation domains — the token is the leftmost label; this service
 * is the shared verification core.
 */
@Injectable()
export class ValidationCallbackService {
  private readonly ingestHits = new Map<string, number[]>();

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly policies: ValidationPoliciesService,
  ) {}

  async issueToken(user: RequestUser, workspaceId: string, input: { requestId?: string; sessionId?: string; ttlSeconds?: number }) {
    requireValidationPermission(user, "RUN_SAFE_VALIDATION");
    const policy = await this.policies.getPolicy(workspaceId);
    if (!policy.callbackEnabled) {
      throw new BadRequestException("callback validation is not enabled for this workspace (§77)");
    }
    const ttl = Math.min(Math.max(input.ttlSeconds ?? 600, 60), 3600);
    const issued = issueCallbackToken(ttl);
    const row = await this.prisma.validationCallbackToken.create({
      data: {
        tokenHash: issued.tokenHash, workspaceId,
        requestId: input.requestId, sessionId: input.sessionId,
        expiresAt: new Date(issued.expiresAt),
      },
    });
    // The raw token is returned exactly once; only its hash persists.
    return { id: row.id, token: issued.token, expiresAt: issued.expiresAt, workspaceId, sessionId: input.sessionId ?? null };
  }

  private rateLimit(key: string, limit: number, windowMs: number): void {
    const now = Date.now();
    const hits = (this.ingestHits.get(key) ?? []).filter((t) => t > now - windowMs);
    if (hits.length >= limit) throw new HttpException("callback ingestion rate limit exceeded (§48)", 429);
    hits.push(now);
    this.ingestHits.set(key, hits);
  }

  /** Public ingestion: no auth — the token correlates, it does not
   *  authorize (§48). Returns an opaque acknowledgement only. */
  async ingest(presentedToken: string, input: { kind?: string; sourceIp?: string }) {
    this.rateLimit(`token:${hashCallbackToken(presentedToken)}`, 30, 60_000);
    if (input.sourceIp) this.rateLimit(`ip:${input.sourceIp}`, 120, 60_000);
    const tokenHash = hashCallbackToken(presentedToken);
    const stored = await this.prisma.validationCallbackToken.findUnique({ where: { tokenHash } });
    if (!stored) throw new HttpException("unknown callback token", 404);
    const verdict = verifyCallbackToken({
      presentedToken,
      stored: {
        tokenHash: stored.tokenHash, workspaceId: stored.workspaceId,
        sessionId: stored.sessionId, expiresAt: stored.expiresAt.toISOString(),
        consumedAt: stored.consumedAt?.toISOString() ?? null,
      },
      workspaceId: stored.workspaceId,
      ...(stored.sessionId ? { sessionId: stored.sessionId } : {}),
      now: new Date(),
    });
    if (!verdict.ok) throw new HttpException(`callback rejected: ${verdict.reasonCode}`, 410);
    await this.prisma.validationCallbackToken.update({
      where: { id: stored.id }, data: { consumedAt: new Date() },
    });
    const event = await this.prisma.validationCallbackEvent.create({
      data: {
        workspaceId: stored.workspaceId, tokenId: stored.id, sessionId: stored.sessionId,
        kind: input.kind === "DNS" ? "DNS" : "HTTP",
        sourceIp: input.sourceIp,
      },
    });
    return { received: true, eventId: event.id };
  }
}
