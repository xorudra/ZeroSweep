/**
 * Prompt 17 — merge helper for mobile payloads (§52): several static
 * adapters contribute to ONE build inventory. Merging is union with
 * identity-based dedup; posture facts merge key-wise (later, more
 * specific tool output wins per key).
 */
import type { NormalizedMobileData } from "../findings/finding.types";

export function emptyMobileData(source: string): NormalizedMobileData {
  return {
    permissions: [], components: [], deepLinks: [], endpoints: [],
    nativeLibraries: [], signing: [], sdkInventory: [], source,
  };
}

export function mergeMobileData(base: NormalizedMobileData, extra: NormalizedMobileData): NormalizedMobileData {
  const dedup = <T,>(items: T[], key: (x: T) => string): T[] => {
    const seen = new Set<string>();
    const out: T[] = [];
    for (const item of items) {
      const k = key(item);
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(item);
    }
    return out;
  };
  return {
    applicationRef: base.applicationRef ?? extra.applicationRef,
    platform: base.platform ?? extra.platform,
    versionName: base.versionName ?? extra.versionName,
    versionCode: base.versionCode ?? extra.versionCode,
    minOsVersion: base.minOsVersion ?? extra.minOsVersion,
    targetOsVersion: base.targetOsVersion ?? extra.targetOsVersion,
    permissions: dedup([...base.permissions, ...extra.permissions], (p) => p.name),
    components: dedup([...base.components, ...extra.components], (c) => `${c.kind}:${c.name}`),
    deepLinks: dedup([...base.deepLinks, ...extra.deepLinks], (d) => `${d.scheme}://${d.host ?? ""}${d.pathPrefix ?? ""}`),
    endpoints: dedup([...base.endpoints, ...extra.endpoints], (e) => e.url),
    nativeLibraries: dedup([...base.nativeLibraries, ...extra.nativeLibraries], (l) => l.path),
    signing: dedup([...base.signing, ...extra.signing], (s) => `${s.subject ?? ""}|${s.fingerprint ?? ""}`),
    sdkInventory: dedup([...base.sdkInventory, ...extra.sdkInventory], (s) => s.name),
    posture: { ...(base.posture ?? {}), ...(extra.posture ?? {}) },
    sourceSnippets: [...(base.sourceSnippets ?? []), ...(extra.sourceSnippets ?? [])],
    source: base.source,
  };
}
