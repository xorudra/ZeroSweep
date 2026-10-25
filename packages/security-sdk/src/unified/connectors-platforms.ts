import {
  ConnectorNotConfiguredError, normalizeExternalRecord, validateConnectorEndpoint,
  type ConnectorCapability, type ConnectorHealth, type ConnectorInstanceConfig,
  type ConnectorTransport, type NormalizedExternalFinding, type VulnerabilityPlatformConnector,
} from "./connectors";

/**
 * The five external vulnerability-platform connectors (Prompt 20
 * §40–§48). Each maps its platform's documented record shape onto the
 * unified model — ZeroSweep's internal model is never forced to match
 * the external one (§41). All field access is defensive: external data
 * is untrusted (§51) and passes the sanitization funnel in
 * normalizeExternalRecord before it can be stored.
 */

function asArray(payload: unknown, keys: string[]): Record<string, unknown>[] {
  if (Array.isArray(payload)) return payload as Record<string, unknown>[];
  if (payload && typeof payload === "object") {
    for (const k of keys) {
      const v = (payload as Record<string, unknown>)[k];
      if (Array.isArray(v)) return v as Record<string, unknown>[];
    }
  }
  return [];
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

async function baseHealth(
  system: string,
  config: ConnectorInstanceConfig,
  transport: ConnectorTransport,
  path: string,
): Promise<ConnectorHealth> {
  const verdict = validateConnectorEndpoint(config);
  if (!verdict.ok) return { status: "NOT_CONFIGURED", detail: verdict.error! };
  try {
    await transport.request({ method: "GET", path });
    return { status: "HEALTHY", detail: `${system} instance responded on the allowlisted endpoint` };
  } catch (err) {
    if (err instanceof ConnectorNotConfiguredError) return { status: "NOT_CONFIGURED", detail: err.message };
    return { status: "UNAVAILABLE", detail: `${system} health check failed: ${(err as Error).message}` };
  }
}

abstract class BaseConnector implements VulnerabilityPlatformConnector {
  abstract readonly system: VulnerabilityPlatformConnector["system"];
  capabilities(_config: ConnectorInstanceConfig): ConnectorCapability[] {
    return ["IMPORT", "EXPORT", "SYNC_FINDINGS"];
  }
  abstract healthCheck(config: ConnectorInstanceConfig, transport: ConnectorTransport): Promise<ConnectorHealth>;
  abstract importFindings(config: ConnectorInstanceConfig, transport: ConnectorTransport, workspaceId: string): Promise<NormalizedExternalFinding[]>;
  async exportFindings(_config: ConnectorInstanceConfig, transport: ConnectorTransport, findings: Record<string, unknown>[]): Promise<{ exported: number; externalIds: string[] }> {
    const externalIds: string[] = [];
    for (const f of findings) {
      const res = (await transport.request({ method: "POST", path: this.exportPath(), body: this.toExternalRecord(f) })) as Record<string, unknown>;
      externalIds.push(String(res.id ?? res._id ?? ""));
    }
    return { exported: findings.length, externalIds };
  }
  protected exportPath(): string { return "/findings"; }
  protected toExternalRecord(f: Record<string, unknown>): Record<string, unknown> {
    return { title: f.title, severity: f.severity, status: this.toExternalStatus(String(f.status ?? "NEW")), description: f.description, cve: f.cve, cwe: f.cwe };
  }
  abstract mapStatus(externalStatus: string): string;
  mapSeverity(externalSeverity: string): string { return externalSeverity; }
  abstract toExternalStatus(unifiedStatus: string): string;
}

// ---------------- DefectDojo (§40–§42) ----------------

export class DefectDojoConnector extends BaseConnector {
  readonly system = "DEFECTDOJO" as const;
  // DefectDojo finding shape: { id, title, severity, cve, cwe, active,
  // verified, duplicate, mitigated, false_p, description, endpoints[] }
  async healthCheck(config: ConnectorInstanceConfig, transport: ConnectorTransport): Promise<ConnectorHealth> {
    return baseHealth("DefectDojo", config, transport, "/api/v2/products/?limit=1");
  }
  async importFindings(_config: ConnectorInstanceConfig, transport: ConnectorTransport, workspaceId: string): Promise<NormalizedExternalFinding[]> {
    const payload = await transport.request({ method: "GET", path: "/api/v2/findings/?limit=1000" });
    return asArray(payload, ["results"]).map((r) => normalizeExternalRecord(workspaceId, {
      externalId: String(r.id ?? ""),
      externalUrl: r.url,
      title: r.title,
      description: r.description,
      severity: this.mapSeverity(String(r.severity ?? "Info")),
      rawSeverity: String(r.severity ?? ""),
      status: this.mapStatus("", r),
      cve: str(r.cve), cwe: r.cwe ? `CWE-${r.cwe}` : undefined,
      host: Array.isArray(r.endpoints) ? str((r.endpoints[0] as Record<string, unknown>)?.host) : undefined,
      sourceDomain: "EXTERNAL_IMPORT",
    }));
  }
  mapStatus(_s: string, r?: Record<string, unknown>): string {
    if (!r) return "NEW";
    if (r.false_p) return "FALSE_POSITIVE";
    if (r.duplicate) return "DUPLICATE";
    if (r.mitigated) return "RESOLVED";
    if (r.verified) return "CONFIRMED";
    if (r.active) return "IN_PROGRESS";
    return "NEW";
  }
  override mapSeverity(s: string): string { return s === "Info" ? "INFORMATIONAL" : s.toUpperCase(); }
  toExternalStatus(unified: string): string {
    return unified; // DefectDojo sync uses flags; the status string is carried for the record
  }
  protected override exportPath(): string { return "/api/v2/findings/"; }
}

// ---------------- Faraday (§45) ----------------

export class FaradayConnector extends BaseConnector {
  readonly system = "FARADAY" as const;
  // Faraday vuln shape: { _id, name, severity, status, desc, refs[], hostnames[] }
  async healthCheck(config: ConnectorInstanceConfig, transport: ConnectorTransport): Promise<ConnectorHealth> {
    return baseHealth("Faraday", config, transport, "/faraday/info");
  }
  async importFindings(_config: ConnectorInstanceConfig, transport: ConnectorTransport, workspaceId: string): Promise<NormalizedExternalFinding[]> {
    const payload = await transport.request({ method: "GET", path: "/faraday/vulns" });
    return asArray(payload, ["vulns", "rows"]).map((r) => {
      const refs = Array.isArray(r.refs) ? r.refs.map(String) : [];
      const cve = refs.find((x) => /^CVE-/i.test(x));
      return normalizeExternalRecord(workspaceId, {
        externalId: String(r._id ?? r.id ?? ""),
        title: r.name,
        description: r.desc,
        severity: this.mapSeverity(String(r.severity ?? "info")),
        status: this.mapStatus(String(r.status ?? "opened")),
        cve,
        host: Array.isArray(r.hostnames) ? str(r.hostnames[0]) : undefined,
        sourceDomain: "EXTERNAL_IMPORT",
      });
    });
  }
  mapStatus(s: string): string {
    switch (s.toLowerCase()) {
      case "closed": return "RESOLVED";
      case "confirmed": return "CONFIRMED";
      case "re-opened": case "reopened": return "REOPENED";
      default: return "NEW"; // opened
    }
  }
  override mapSeverity(s: string): string { return s.toLowerCase() === "informational" || s.toLowerCase() === "info" ? "INFORMATIONAL" : s.toUpperCase(); }
  toExternalStatus(unified: string): string {
    switch (unified) {
      case "RESOLVED": return "closed";
      case "CONFIRMED": return "confirmed";
      case "REOPENED": return "re-opened";
      default: return "opened";
    }
  }
  protected override exportPath(): string { return "/faraday/vulns"; }
}

// ---------------- Dradis (§46) ----------------

export class DradisConnector extends BaseConnector {
  readonly system = "DRADIS" as const;
  // Dradis issue shape: { id, title, text } — text carries #[Field]#
  // blocks (reporting interoperability format).
  async healthCheck(config: ConnectorInstanceConfig, transport: ConnectorTransport): Promise<ConnectorHealth> {
    return baseHealth("Dradis", config, transport, "/dradis/issues?limit=1");
  }
  async importFindings(_config: ConnectorInstanceConfig, transport: ConnectorTransport, workspaceId: string): Promise<NormalizedExternalFinding[]> {
    const payload = await transport.request({ method: "GET", path: "/dradis/issues" });
    return asArray(payload, ["issues"]).map((r) => {
      const text = typeof r.text === "string" ? r.text : "";
      const field = (name: string) => {
        const m = text.match(new RegExp(`#\\[${name}\\]#\\s*\\n([^#]*)`, "i"));
        return m?.[1]?.trim();
      };
      const cve = text.match(/CVE-\d{4}-\d{4,7}/i)?.[0];
      return normalizeExternalRecord(workspaceId, {
        externalId: String(r.id ?? ""),
        title: r.title,
        description: field("Description") ?? text,
        severity: this.mapSeverity(field("Severity") ?? "Info"),
        status: "NEW", // Dradis issues carry no workflow state in the interop format
        cve,
        evidence: field("Evidence"),
        sourceDomain: "EXTERNAL_IMPORT",
      });
    });
  }
  mapStatus(_s: string): string { return "NEW"; }
  override mapSeverity(s: string): string { return s === "Info" ? "INFORMATIONAL" : s.toUpperCase(); }
  toExternalStatus(unified: string): string { return unified; }
  protected override exportPath(): string { return "/dradis/issues"; }
}

// ---------------- PlexTrac (§47 — optional, license-aware) ----------------

export class PlexTracConnector extends BaseConnector {
  readonly system = "PLEXTRAC" as const;
  override capabilities(config: ConnectorInstanceConfig): ConnectorCapability[] {
    // §47: never assume license/access exists.
    return config.licenseConfirmed ? ["IMPORT", "EXPORT", "SYNC_FINDINGS"] : [];
  }
  async healthCheck(config: ConnectorInstanceConfig, transport: ConnectorTransport): Promise<ConnectorHealth> {
    if (!config.licenseConfirmed) {
      return { status: "LICENSE_UNAVAILABLE", detail: "PlexTrac is a commercial platform; no licensed installation is confirmed — connector stays inert (§47)" };
    }
    return baseHealth("PlexTrac", config, transport, "/plextrac/findings?limit=1");
  }
  async importFindings(config: ConnectorInstanceConfig, transport: ConnectorTransport, workspaceId: string): Promise<NormalizedExternalFinding[]> {
    if (!config.licenseConfirmed) throw new ConnectorNotConfiguredError("PLEXTRAC");
    const payload = await transport.request({ method: "GET", path: "/plextrac/findings" });
    return asArray(payload, ["findings", "data"]).map((r) => normalizeExternalRecord(workspaceId, {
      externalId: String(r.id ?? ""),
      title: r.title,
      description: r.description,
      severity: this.mapSeverity(String(r.severity ?? "informational")),
      status: this.mapStatus(String(r.status ?? "open")),
      cve: str(r.cve), cwe: str(r.cwe),
      sourceDomain: "EXTERNAL_IMPORT",
    }));
  }
  mapStatus(s: string): string { return s.toLowerCase() === "closed" ? "RESOLVED" : "NEW"; }
  override mapSeverity(s: string): string { return s.toLowerCase() === "informational" ? "INFORMATIONAL" : s.toUpperCase(); }
  toExternalStatus(unified: string): string { return unified === "RESOLVED" ? "closed" : "open"; }
  protected override exportPath(): string { return "/plextrac/findings"; }
}

// ---------------- Serpico (§48 — legacy report-data interop) ----------------

export class SerpicoConnector extends BaseConnector {
  readonly system = "SERPICO" as const;
  // Serpico finding shape: { id, title, vuln_type, severity_rating (0-4 or label), status, description }
  async healthCheck(config: ConnectorInstanceConfig, transport: ConnectorTransport): Promise<ConnectorHealth> {
    return baseHealth("Serpico", config, transport, "/serpico/findings?limit=1");
  }
  async importFindings(_config: ConnectorInstanceConfig, transport: ConnectorTransport, workspaceId: string): Promise<NormalizedExternalFinding[]> {
    const payload = await transport.request({ method: "GET", path: "/serpico/findings" });
    return asArray(payload, ["findings"]).map((r) => normalizeExternalRecord(workspaceId, {
      externalId: String(r.id ?? ""),
      title: r.title,
      description: r.description,
      severity: this.mapSeverity(String(r.severity_rating ?? "Info")),
      status: this.mapStatus(String(r.status ?? "Open")),
      sourceDomain: "EXTERNAL_IMPORT",
    }));
  }
  mapStatus(s: string): string { return s.toLowerCase() === "closed" ? "RESOLVED" : "NEW"; }
  override mapSeverity(s: string): string {
    // Serpico historically rates 4=Critical … 0=None as well as labels.
    const numeric: Record<string, string> = { "4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFORMATIONAL" };
    return numeric[s] ?? (s === "Info" ? "INFORMATIONAL" : s.toUpperCase());
  }
  toExternalStatus(unified: string): string { return unified === "RESOLVED" ? "Closed" : "Open"; }
  protected override exportPath(): string { return "/serpico/findings"; }
}

export const PLATFORM_CONNECTORS: Record<string, VulnerabilityPlatformConnector> = {
  DEFECTDOJO: new DefectDojoConnector(),
  FARADAY: new FaradayConnector(),
  DRADIS: new DradisConnector(),
  PLEXTRAC: new PlexTracConnector(),
  SERPICO: new SerpicoConnector(),
};
