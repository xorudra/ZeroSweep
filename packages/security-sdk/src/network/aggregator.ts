import type { NormalizedService } from "../findings/finding.types";

/**
 * PortResultAggregator (Prompt 10 §49/§31): merge port/service
 * discoveries from Nmap, Naabu, RustScan and Masscan into ONE canonical
 * service per (host, transport, port). Provenance is preserved as the
 * union of sources; richer evidence wins field-by-field:
 * - state: OPEN outranks OPEN_FILTERED, which outranks FILTERED/CLOSED —
 *   a scanner that proved a port open is never downgraded by one that
 *   merely didn't see it.
 * - product/version/CPE/TLS: the highest-confidence reporter wins;
 *   Nmap's probed fingerprint (confidence from its conf value) normally
 *   carries the real data, fast scanners contribute the port itself.
 * Duplicate port/service rows are never created (§31).
 */
const STATE_RANK: Record<string, number> = { OPEN: 4, OPEN_FILTERED: 3, UNKNOWN: 2, FILTERED: 1, CLOSED: 0 };

export function serviceKey(s: { host: string; port: number; protocol: string }): string {
  return `${s.host.toLowerCase()}|${s.protocol.toLowerCase()}|${s.port}`;
}

export function mergeServices(inputs: NormalizedService[]): NormalizedService[] {
  const byKey = new Map<string, NormalizedService>();
  for (const svc of inputs) {
    const key = serviceKey(svc);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...svc, sources: [...new Set(svc.sources ?? [])] });
      continue;
    }
    const sources = [...new Set([...(existing.sources ?? []), ...(svc.sources ?? [])])].sort();
    const richer = (svc.confidence ?? 0) > (existing.confidence ?? 0) ? svc : existing;
    const poorer = richer === svc ? existing : svc;
    const merged: NormalizedService = {
      ...poorer,
      ...richer,
      host: existing.host, port: existing.port, protocol: existing.protocol,
      sources,
      state: (STATE_RANK[svc.state ?? "UNKNOWN"] ?? 0) > (STATE_RANK[existing.state ?? "UNKNOWN"] ?? 0) ? svc.state : existing.state,
      // Gap-fill descriptive fields from whichever side has them.
      name: richer.name ?? poorer.name,
      product: richer.product ?? poorer.product,
      version: richer.version ?? poorer.version,
      cpe: richer.cpe ?? poorer.cpe,
      banner: richer.banner ?? poorer.banner,
      tls: richer.tls ?? poorer.tls,
      confidence: Math.max(existing.confidence ?? 0, svc.confidence ?? 0) || undefined,
    };
    // Preserve the richer reporter's own fields where the merge above
    // would have kept a gap-filled value from the poorer side.
    if (!merged.name && poorer.name) merged.name = poorer.name;
    byKey.set(key, merged);
  }
  return [...byKey.values()].sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port);
}

/** §72 network summary over merged inventory: computed ONLY from real
 *  merged records — the GUI renders exactly these numbers. */
export function networkSummary(services: NormalizedService[], hosts: number, findings: number, duplicatesMerged: number): Record<string, number> {
  const open = services.filter((s) => (s.state ?? "OPEN") === "OPEN");
  return {
    hostsDiscovered: hosts,
    openTcpPorts: open.filter((s) => s.protocol === "tcp").length,
    openUdpPorts: open.filter((s) => s.protocol === "udp").length,
    servicesIdentified: open.filter((s) => s.name && s.name !== "unknown").length,
    tlsServices: open.filter((s) => s.tls).length,
    webServices: open.filter((s) => ["http", "https", "http-alt", "https-alt"].includes((s.name ?? "").toLowerCase()) || [80, 443, 8000, 8080, 8443].includes(s.port)).length,
    findings,
    duplicatesMerged,
  };
}
