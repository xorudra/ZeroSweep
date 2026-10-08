/**
 * Network baselines + drift (Prompt 33 §101–§104, §153).
 *
 * Baselines are IMMUTABLE, VERSIONED snapshots of a host's observed
 * network posture (§104). Comparison is purely mechanical: hosts
 * added/removed, ports opened/closed, services changed, versions
 * changed, TLS changed, new vulnerabilities. A drift event is a
 * CONTEXTUAL signal (§103) — e.g. a new remote-management service on a
 * critical production asset raises risk context; drift itself never
 * mints a vulnerability finding.
 */

export interface HostPostureSnapshot {
  host: string;
  criticality: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNSPECIFIED";
  environment: string;
  services: Array<{ port: number; transport: string; service?: string; version?: string; tls?: boolean }>;
  vulnerabilities: string[]; // fingerprints/CVE ids present
}

export interface NetworkBaselineData {
  version: number;
  capturedAt: string;
  hosts: HostPostureSnapshot[];
}

export type DriftKind =
  | "HOST_ADDED" | "HOST_REMOVED" | "PORT_OPENED" | "PORT_CLOSED"
  | "SERVICE_ADDED" | "SERVICE_CHANGED" | "VERSION_CHANGED"
  | "TLS_CHANGED" | "NEW_VULNERABILITY";

export interface DriftEvent {
  kind: DriftKind;
  host: string;
  detail: string;
  /** §103: contextual — elevated when a sensitive service appears on a
   *  critical production asset; never a vulnerability by itself. */
  riskSignal: "ELEVATED" | "STANDARD";
  signalReason: string;
}

const SENSITIVE_PORTS = new Set([22, 23, 3389, 5900, 5985, 5986, 2375, 2376, 6443, 10250]);

export function compareNetworkSnapshots(baseline: NetworkBaselineData, current: HostPostureSnapshot[]): DriftEvent[] {
  const events: DriftEvent[] = [];
  const baseByHost = new Map(baseline.hosts.map((h) => [h.host, h]));
  const currentByHost = new Map(current.map((h) => [h.host, h]));

  const signal = (host: HostPostureSnapshot | undefined, port?: number): Pick<DriftEvent, "riskSignal" | "signalReason"> => {
    if (host && typeof port === "number" && SENSITIVE_PORTS.has(port) && (host.criticality === "CRITICAL" || host.criticality === "HIGH") && /prod/i.test(host.environment)) {
      return { riskSignal: "ELEVATED", signalReason: `Sensitive service (port ${port}) changed on a ${host.criticality.toLowerCase()} production asset (§103)` };
    }
    return { riskSignal: "STANDARD", signalReason: "Routine posture change (§101)" };
  };

  for (const [host, cur] of currentByHost) {
    if (!baseByHost.has(host)) {
      events.push({ kind: "HOST_ADDED", host, detail: `Host ${host} appeared since baseline v${baseline.version}`, ...signal(cur) });
    }
  }
  for (const [host] of baseByHost) {
    if (!currentByHost.has(host)) {
      events.push({ kind: "HOST_REMOVED", host, detail: `Host ${host} no longer observed (baseline v${baseline.version}) — may be down, filtered or decommissioned; not assumed (§101)`, riskSignal: "STANDARD", signalReason: "Host absence is ambiguous evidence (§101)" });
    }
  }

  for (const [host, cur] of currentByHost) {
    const base = baseByHost.get(host);
    if (!base) continue;
    const key = (s: { port: number; transport: string }) => `${s.port}/${s.transport}`;
    const baseSvc = new Map(base.services.map((s) => [key(s), s]));
    const curSvc = new Map(cur.services.map((s) => [key(s), s]));
    for (const [k, svc] of curSvc) {
      if (!baseSvc.has(k)) {
        events.push({ kind: "SERVICE_ADDED", host, detail: `New service ${svc.service ?? "unknown"} on ${host}:${svc.port}/${svc.transport}`, ...signal(cur, svc.port) });
      }
    }
    for (const [k, svc] of baseSvc) {
      if (!curSvc.has(k)) {
        events.push({ kind: "PORT_CLOSED", host, detail: `Service ${svc.service ?? "unknown"} on ${host}:${svc.port}/${svc.transport} no longer observed`, ...signal(cur, svc.port) });
      }
    }
    for (const [k, svc] of curSvc) {
      const prev = baseSvc.get(k);
      if (!prev) continue;
      if ((prev.service ?? "") !== (svc.service ?? "")) {
        events.push({ kind: "SERVICE_CHANGED", host, detail: `Service on ${host}:${svc.port} changed ${prev.service ?? "?"} → ${svc.service ?? "?"}`, ...signal(cur, svc.port) });
      }
      if ((prev.version ?? "") !== (svc.version ?? "") && (prev.version || svc.version)) {
        events.push({ kind: "VERSION_CHANGED", host, detail: `Version on ${host}:${svc.port} changed ${prev.version ?? "?"} → ${svc.version ?? "?"} — patch or upgrade evidence for verification (§111)`, ...signal(cur, svc.port) });
      }
      if ((prev.tls ?? false) !== (svc.tls ?? false)) {
        events.push({ kind: "TLS_CHANGED", host, detail: `TLS posture on ${host}:${svc.port} changed (${prev.tls ? "TLS" : "no TLS"} → ${svc.tls ? "TLS" : "no TLS"})`, ...signal(cur, svc.port) });
      }
    }
    const baseVulns = new Set(base.vulnerabilities);
    for (const v of cur.vulnerabilities) {
      if (!baseVulns.has(v)) {
        events.push({ kind: "NEW_VULNERABILITY", host, detail: `New vulnerability signal ${v} on ${host} since baseline v${baseline.version}`, ...signal(cur) });
      }
    }
  }
  return events;
}
