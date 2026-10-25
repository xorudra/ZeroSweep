import { Injectable } from "@nestjs/common";
import { analyticsCacheKey, analyticsCachePrefix } from "@zerosweep/security-sdk";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { classificationCeiling, permissionsFor } from "./permissions";

interface Entry { value: unknown; expiresAt: number; tenantTag: string }

/**
 * Tenant-safe analytics cache (§122–§124). Keys are content hashes of
 * organization + workspace + role + permission fingerprint +
 * classification ceiling + view + filters — a cached Tenant A result
 * is structurally unreachable for Tenant B (§123/§142). TTL-bounded;
 * projection writes invalidate the workspace namespace (§124).
 */
@Injectable()
export class AnalyticsCacheService {
  private readonly store = new Map<string, Entry>();
  private readonly ttlMs = 60_000;

  keyFor(user: RequestUser, workspaceId: string, view: string, filters: unknown): string {
    return analyticsCacheKey({
      organizationId: user.organizationId, workspaceId, role: user.role,
      permissions: permissionsFor(user), classificationCeiling: classificationCeiling(user),
      view, filters,
    });
  }

  get<T>(key: string): T | null {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { this.store.delete(key); return null; }
    return entry.value as T;
  }

  set(user: RequestUser, workspaceId: string, key: string, value: unknown): void {
    this.store.set(key, {
      value, expiresAt: Date.now() + this.ttlMs,
      tenantTag: analyticsCachePrefix(user.organizationId, workspaceId),
    });
  }

  invalidateWorkspace(user: RequestUser, workspaceId: string): void {
    const tag = analyticsCachePrefix(user.organizationId, workspaceId);
    for (const [key, entry] of this.store.entries()) {
      if (entry.tenantTag === tag) this.store.delete(key);
    }
  }
}
