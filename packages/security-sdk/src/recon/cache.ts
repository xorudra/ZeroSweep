import type { NormalizedSecurityResult } from "../findings/finding.types";

/**
 * Tenant-safe recon cache (Prompt 5 §49). Passive sources (archives, CT
 * logs) change slowly, so fragments may be cached briefly — under three
 * non-negotiable rules:
 *  1. The cache key includes organization + workspace: a cross-tenant hit
 *     is structurally impossible.
 *  2. Cached fragments are NEVER trusted for scope: callers must run them
 *     through ReconResultAggregator / processNormalizedResult again, which
 *     re-evaluates the CURRENT scope rules on every use.
 *  3. Entries expire; nothing here is a source of truth.
 */
export class TenantSafeReconCache {
  private readonly entries = new Map<string, { at: number; result: NormalizedSecurityResult }>();

  constructor(
    private readonly ttlMs = 15 * 60 * 1000,
    private readonly now: () => number = () => Date.now(),
  ) {}

  static key(organizationId: string, workspaceId: string, toolSlug: string, targetHost: string, configFingerprint: string): string {
    return `${organizationId}:${workspaceId}:${toolSlug}:${targetHost.toLowerCase()}:${configFingerprint}`;
  }

  get(key: string): NormalizedSecurityResult | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (this.now() - entry.at > this.ttlMs) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.result;
  }

  set(key: string, result: NormalizedSecurityResult): void {
    this.entries.set(key, { at: this.now(), result });
  }

  get size(): number {
    return this.entries.size;
  }
}
