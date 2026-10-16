import { randomBytes } from "node:crypto";
import { promises as dns } from "node:dns";
import { request as httpsRequest } from "node:https";
import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { createTargetSchema, paginationSchema } from "@dsrclone/validation";
import { blockedTargetReason, cloudEndpointVerdict } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { parseOrThrow } from "../../common/parse";
import { assertTargetInOrg, resolveWorkspace } from "../../common/tenant";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { AuditService } from "../audit/audit.service";

/** Pinned HTTPS fetch seam: connects to the already-validated
 *  `address` while TLS SNI + certificate validation keep the original
 *  hostname, so the name is never re-resolved at fetch time (DNS
 *  rebinding TOCTOU). Redirects are never followed — a 3xx resolves
 *  with ok=false. Overridable in tests (same pattern as the
 *  notification router's resolver seam). */
export type PinnedFetch = (
  url: string, address: string, family: number,
) => Promise<{ ok: boolean; status: number; text: string }>;

export const pinnedHttpsFetch: PinnedFetch = (url, address, family) => new Promise((resolve, reject) => {
  const u = new URL(url);
  const req = httpsRequest(
    {
      hostname: u.hostname, servername: u.hostname, port: 443,
      path: `${u.pathname}${u.search}`, method: "GET",
      lookup: (_hostname, _options, callback) => callback(null, address, family),
      timeout: 5000,
    },
    (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (chunk: Buffer) => { size += chunk.length; if (size <= 65536) chunks.push(chunk); });
      res.on("end", () => resolve({
        ok: (res.statusCode ?? 0) >= 200 && (res.statusCode ?? 0) < 300,
        status: res.statusCode ?? 0,
        text: Buffer.concat(chunks).toString("utf8"),
      }));
    },
  );
  req.on("timeout", () => req.destroy(new Error("pinned fetch timed out")));
  req.on("error", reject);
  req.end();
});

@Injectable()
export class TargetsService {
  pinnedFetch: PinnedFetch = pinnedHttpsFetch;
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async list(user: RequestUser, query: unknown) {
    const { page = 1, pageSize = 20, search } = parseOrThrow(paginationSchema, query ?? {});
    const workspace = await resolveWorkspace(this.prisma, user);
    const where = {
      workspaceId: workspace.id, deletedAt: null,
      ...(search ? { OR: [{ name: { contains: search } }, { value: { contains: search } }] } : {}),
    } as never;
    const [items, total] = await Promise.all([
      this.prisma.target.findMany({ where, orderBy: { createdAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize }),
      this.prisma.target.count({ where }),
    ]);
    return { items, total, page, pageSize };
  }

  async create(user: RequestUser, body: unknown) {
    const data = parseOrThrow(createTargetSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    const target = await this.prisma.target.create({
      data: { workspaceId: workspace.id, name: data.name, type: data.type as never, value: data.value, description: data.description, status: "PENDING_VERIFICATION", createdBy: user.id },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: "TARGET_CREATED", resourceType: "Target", resourceId: target.id });
    return target;
  }

  async get(user: RequestUser, id: string) {
    return assertTargetInOrg(this.prisma, user, id);
  }

  /** Start an ownership-verification challenge. Nothing is marked verified
   *  until a real check passes — no fake verification. */
  async startVerification(user: RequestUser, targetId: string, method: "DNS_TXT" | "HTTP_FILE" | "MANUAL_APPROVAL") {
    const target = await assertTargetInOrg(this.prisma, user, targetId);
    const challenge = `dsrclone-verify=${randomBytes(16).toString("hex")}`;
    const verification = await this.prisma.targetVerification.create({
      data: {
        targetId: target.id, method, requestedBy: user.id,
        challenge: method === "HTTP_FILE" ? `${challenge}` : challenge,
        expiresAt: new Date(Date.now() + 72 * 3600 * 1000),
      },
    });
    const instructions =
      method === "DNS_TXT"
        ? `Add a TXT record to ${target.value}: ${challenge}`
        : method === "HTTP_FILE"
          ? `Serve the challenge text at https://${target.value}/.well-known/dsrclone-verification.txt`
          : "An administrator will review ownership evidence and approve manually.";
    return { verification, instructions };
  }

  /** Check a pending challenge. DNS_TXT performs a real DNS lookup;
   *  MANUAL_APPROVAL can only be completed by an OWNER/ADMIN. */
  async checkVerification(user: RequestUser, targetId: string, verificationId: string) {
    const target = await assertTargetInOrg(this.prisma, user, targetId);
    const verification = await this.prisma.targetVerification.findFirst({ where: { id: verificationId, targetId: target.id } });
    if (!verification) throw new NotFoundException("Verification not found");
    if (verification.expiresAt && verification.expiresAt < new Date()) {
      await this.prisma.targetVerification.update({ where: { id: verification.id }, data: { status: "EXPIRED" } });
      return { status: "EXPIRED" };
    }
    let verified = false;
    if (verification.method === "DNS_TXT") {
      try {
        const records = await dns.resolveTxt(target.value);
        verified = records.flat().some((r) => r.includes(verification.challenge));
      } catch { verified = false; }
    } else if (verification.method === "MANUAL_APPROVAL") {
      // Independence (security audit 2026-10-16 run-2): manual approval is
      // a second-person control — the approver must be an OWNER/ADMIN who
      // is neither the target's creator nor the person who opened this
      // verification. Role alone never verifies a target.
      verified = (user.role === "OWNER" || user.role === "ADMIN")
        && user.id !== target.createdBy
        && (verification.requestedBy == null || user.id !== verification.requestedBy);
    } else {
      // HTTP_FILE check fetches the well-known file over HTTPS (plain
      // ownership proof, not a security scan). Launch Safety A5: the URL
      // is built from a user-registered hostname, so before fetching it
      // passes the same endpoint verdict the cloud connectors use
      // (cloudsec §101 — HTTPS only, no embedded credentials, host not in
      // a blocked loopback/private/link-local/metadata range) AND every
      // address the host resolves to must clear blockedTargetReason —
      // a public name resolving into private space is refused too.
      // The fetch itself is PINNED to the first validated address
      // (pinnedHttpsFetch): the hostname is never re-resolved at fetch
      // time, closing the DNS-rebinding TOCTOU between check and fetch.
      // Redirects are never followed: a redirect is a failed check.
      const url = `https://${target.value}/.well-known/dsrclone-verification.txt`;
      const verdict = cloudEndpointVerdict(url);
      if (!verdict.allowed) {
        verified = false;
      } else {
        try {
          const addresses = await dns.lookup(target.value, { all: true });
          if (addresses.length === 0 || addresses.some((a) => blockedTargetReason(a.address))) {
            verified = false;
          } else {
            const pinned = addresses[0]!;
            const res = await this.pinnedFetch(url, pinned.address, pinned.family);
            verified = res.ok && res.text.includes(verification.challenge);
          }
        } catch { verified = false; }
      }
    }
    if (verified) {
      await this.prisma.targetVerification.update({ where: { id: verification.id }, data: { status: "VERIFIED", verifiedAt: new Date() } });
      await this.prisma.target.update({ where: { id: target.id }, data: { verified: true, status: "VERIFIED" } });
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: target.workspaceId, action: "TARGET_VERIFIED", resourceType: "Target", resourceId: target.id });
    }
    return { status: verified ? "VERIFIED" : "PENDING", detail: verified ? "Ownership verified" : "Challenge not found yet" };
  }
}
