import type {
  NormalizedAsset, NormalizedHttpTransaction, NormalizedPacketCapture, NormalizedService,
} from "../findings/finding.types";
import { parseJsonLines, str, num } from "../recon/parsers-common";
import { makeFinding, type ParsedObservation } from "../vuln/parsers-vuln";
import type { NormalizedVulnFinding } from "../vuln/types";
import { classifyScriptOutput, classifyServiceChecks, type ExposureObservation } from "./network-checks";
import { sanitizeBanner, sanitizeScannerText } from "./sanitize";
import { nmapScriptPolicy } from "./script-policy";
import { childrenNamed, firstChild, parseXmlLite } from "./xml-lite";

/**
 * Network parsers (Prompt 10 §15–§16/§45). Every parser turns one tool's
 * raw output into normalized fragments and NEVER throws on hostile or
 * malformed records: bad input becomes warnings. Open ports/services are
 * inventory; findings appear only through the governed check policy in
 * network-checks.ts (§37).
 */
export interface ParsedNetwork {
  assets: NormalizedAsset[];
  endpoints: [];
  technologies: [];
  services: NormalizedService[];
  findings: NormalizedVulnFinding[];
  observations: ParsedObservation[];
  exposures: ExposureObservation[];
  transactions: NormalizedHttpTransaction[];
  captures: NormalizedPacketCapture[];
  records: number;
  warnings: string[];
  metrics: Record<string, number>;
}

export interface NetworkParser {
  readonly tool: string;
  parse(raw: string): ParsedNetwork;
}

export function emptyNetworkParsed(): ParsedNetwork {
  return { assets: [], endpoints: [], technologies: [], services: [], findings: [], observations: [], exposures: [], transactions: [], captures: [], records: 0, warnings: [], metrics: {} };
}

function portState(raw: string | undefined): NormalizedService["state"] {
  switch ((raw ?? "").toLowerCase()) {
    case "open": return "OPEN";
    case "closed": return "CLOSED";
    case "filtered": return "FILTERED";
    case "open|filtered": return "OPEN_FILTERED";
    default: return "UNKNOWN";
  }
}

const TLS_SERVICE_NAMES = new Set(["https", "ssl", "tls", "ldaps", "ftps", "smtps", "pop3s", "imaps"]);
function serviceIsTls(name: string | undefined, tunnel: string | undefined, port: number): boolean {
  if (tunnel === "ssl" || tunnel === "tls") return true;
  const n = (name ?? "").toLowerCase();
  if (TLS_SERVICE_NAMES.has(n)) return true;
  return (port === 443 || port === 8443) && (n === "http" || n === "https");
}

/** Fold the governed check policy over a parser's services + script
 *  observations: findings and exposure observations land on the result. */
function applyNetworkChecks(
  out: ParsedNetwork,
  tool: string,
  scriptOutputs: Array<{ host: string; port: number; protocol?: string; scriptId: string; output: string }>,
): void {
  const { findings, exposures } = classifyServiceChecks(out.services);
  for (const f of findings) {
    out.findings.push(makeFinding({
      title: f.title, description: f.description, severity: f.severity, vulnClass: f.vulnClass,
      host: f.host, port: f.port, protocol: f.protocol,
      sourceTool: tool, sourceConfidence: f.confidence, signatureFamily: f.checkId,
      evidenceSummary: f.evidence,
      evidenceDetail: { matchedAt: `${f.host}:${f.port}`, checkId: f.checkId, signatureFamily: f.checkId },
    }));
  }
  out.exposures.push(...exposures);
  for (const s of scriptOutputs) {
    const meta = nmapScriptPolicy.classify(s.scriptId);
    const confirmed = classifyScriptOutput({
      host: s.host, port: s.port, protocol: s.protocol, scriptId: s.scriptId, output: s.output,
      declaredVulnClass: meta.produces === "FINDING" ? meta.vulnClass : undefined,
    });
    if (confirmed) {
      out.findings.push(makeFinding({
        title: confirmed.title, description: confirmed.description, severity: confirmed.severity,
        vulnClass: confirmed.vulnClass, host: confirmed.host, port: confirmed.port, protocol: confirmed.protocol,
        sourceTool: tool, sourceConfidence: confirmed.confidence, signatureFamily: confirmed.checkId,
        evidenceSummary: confirmed.evidence,
        evidenceDetail: { matchedAt: `${confirmed.host}:${confirmed.port}`, checkId: confirmed.checkId, signatureFamily: confirmed.checkId },
      }));
    } else if (s.output.trim()) {
      out.observations.push({ kind: "CONFIGURATION", summary: sanitizeScannerText(`${s.scriptId}: ${s.output}`, 512), host: s.host });
    }
  }
}

// ---------------------------------------------------------------------------
// Nmap XML (§15/§16)
// ---------------------------------------------------------------------------

export class NmapParser implements NetworkParser {
  readonly tool = "nmap";

  parse(raw: string): ParsedNetwork {
    const out = emptyNetworkParsed();
    const parsed = parseXmlLite(raw);
    if ("error" in parsed) {
      out.warnings.push(`nmap: XML rejected — ${parsed.error}`);
      return out;
    }
    if (parsed.root.tag !== "nmaprun") {
      out.warnings.push("nmap: root element is not <nmaprun> — no hosts parsed");
      return out;
    }
    const scriptOutputs: Array<{ host: string; port: number; protocol?: string; scriptId: string; output: string }> = [];
    for (const hostNode of childrenNamed(parsed.root, "host")) {
      const status = firstChild(hostNode, "status")?.attrs.state;
      if (status === "down") continue; // down hosts contribute nothing (§29: live hosts become assets)
      const addresses = childrenNamed(hostNode, "address");
      const ipNode = addresses.find((a) => a.attrs.addrtype === "ipv4" || a.attrs.addrtype === "ipv6");
      const ip = ipNode?.attrs.addr;
      if (!ip) continue;
      const hostnames = (firstChild(hostNode, "hostnames") ? childrenNamed(firstChild(hostNode, "hostnames")!, "hostname") : [])
        .map((h) => h.attrs.name).filter((n): n is string => !!n);
      if (status === "up") {
        out.assets.push({ host: ip, ip, type: "HOST", sources: ["nmap"] });
        for (const name of hostnames) {
          out.assets.push({ host: name.toLowerCase(), ip, type: "HOST", sources: ["nmap"] });
        }
        out.records++;
      }
      // OS hints (§35): best osmatch only, accuracy → confidence. A hint,
      // never a fact.
      const osNode = firstChild(hostNode, "os");
      const osMatch = osNode ? firstChild(osNode, "osmatch") : undefined;
      if (osMatch?.attrs.name && status === "up") {
        const accuracy = Number(osMatch.attrs.accuracy ?? "0");
        const asset = out.assets.find((a) => a.host === ip);
        if (asset) {
          asset.osHint = sanitizeScannerText(osMatch.attrs.name, 128);
          asset.osConfidence = Number.isFinite(accuracy) ? Math.min(1, accuracy / 100) : undefined;
        }
      }
      const portsNode = firstChild(hostNode, "ports");
      if (portsNode) {
        for (const portNode of childrenNamed(portsNode, "port")) {
          const port = Number(portNode.attrs.portid);
          if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
          const protocol = (portNode.attrs.protocol ?? "tcp").toLowerCase();
          const state = portState(firstChild(portNode, "state")?.attrs.state);
          const svcNode = firstChild(portNode, "service");
          const name = svcNode?.attrs.name;
          const conf = Number(svcNode?.attrs.conf ?? "");
          const method = svcNode?.attrs.method;
          const confidence = state !== "OPEN" ? undefined
            : method === "table" ? 0.3
            : Number.isFinite(conf) && conf > 0 ? Math.min(1, conf / 10) : 0.6;
          const cpeNode = svcNode ? firstChild(svcNode, "cpe") : undefined;
          out.services.push({
            host: ip, port, protocol,
            ...(name ? { name } : {}),
            ...(svcNode?.attrs.product ? { product: sanitizeScannerText(svcNode.attrs.product, 128) } : {}),
            ...(svcNode?.attrs.version ? { version: sanitizeScannerText(svcNode.attrs.version, 64) } : {}),
            ...(svcNode?.attrs.extrainfo ? { banner: sanitizeBanner(svcNode.attrs.extrainfo) } : {}),
            state,
            ...(serviceIsTls(name, svcNode?.attrs.tunnel, port) ? { tls: true } : {}),
            ...(cpeNode?.text.trim() ? { cpe: cpeNode.text.trim().slice(0, 255) } : {}),
            ...(confidence !== undefined ? { confidence } : {}),
            sources: ["nmap"],
          });
          for (const script of childrenNamed(portNode, "script")) {
            if (script.attrs.id && script.attrs.output) {
              scriptOutputs.push({ host: ip, port, protocol, scriptId: script.attrs.id, output: script.attrs.output });
            }
          }
        }
      }
      const hostScript = firstChild(hostNode, "hostscript");
      if (hostScript) {
        for (const script of childrenNamed(hostScript, "script")) {
          if (script.attrs.id && script.attrs.output) {
            scriptOutputs.push({ host: ip, port: 445, scriptId: script.attrs.id, output: script.attrs.output });
          }
        }
      }
    }
    applyNetworkChecks(out, this.tool, scriptOutputs);
    out.metrics = {
      records: out.records, services: out.services.length,
      findings: out.findings.length, observations: out.observations.length,
    };
    return out;
  }
}

// ---------------------------------------------------------------------------
// Naabu JSONL — fast port discovery (§17)
// ---------------------------------------------------------------------------

export class NaabuParser implements NetworkParser {
  readonly tool = "naabu";

  parse(raw: string): ParsedNetwork {
    const out = emptyNetworkParsed();
    const { records, warnings } = parseJsonLines(raw, this.tool);
    out.warnings.push(...warnings);
    const seenAssets = new Set<string>();
    for (const rec of records) {
      const host = str(rec.host) ?? str(rec.ip);
      const port = num(rec.port);
      if (!host || port === undefined) { out.warnings.push("naabu: record without host/port skipped"); continue; }
      if (!seenAssets.has(host)) {
        seenAssets.add(host);
        out.assets.push({ host, ip: str(rec.ip) ?? host, type: "HOST", sources: ["naabu"] });
      }
      out.services.push({
        host, port, protocol: (str(rec.protocol) ?? "tcp").toLowerCase(),
        state: "OPEN",
        ...(rec.tls === true ? { tls: true } : {}),
        confidence: 0.5, // port discovery only — no version evidence (§33)
        sources: ["naabu"],
      });
      out.records++;
    }
    applyNetworkChecks(out, this.tool, []);
    out.metrics = { records: out.records, services: out.services.length, findings: out.findings.length };
    return out;
  }
}

// ---------------------------------------------------------------------------
// RustScan greppable output (§18): "192.0.2.10 -> [80,443]" lines
// ---------------------------------------------------------------------------

export class RustScanParser implements NetworkParser {
  readonly tool = "rustscan";

  parse(raw: string): ParsedNetwork {
    const out = emptyNetworkParsed();
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const greppable = trimmed.match(/^(\S+)\s*->\s*\[([0-9,]*)\]$/);
      const openLine = trimmed.match(/^Open\s+(\S+):(\d+)$/i);
      if (greppable) {
        const host = greppable[1]!;
        out.assets.push({ host, ip: host, type: "HOST", sources: ["rustscan"] });
        for (const p of greppable[2]!.split(",").filter(Boolean)) {
          const port = Number(p);
          if (Number.isInteger(port) && port >= 1 && port <= 65535) {
            out.services.push({ host, port, protocol: "tcp", state: "OPEN", confidence: 0.5, sources: ["rustscan"] });
          }
        }
        out.records++;
      } else if (openLine) {
        const host = openLine[1]!;
        const port = Number(openLine[2]);
        if (!out.assets.some((a) => a.host === host)) out.assets.push({ host, ip: host, type: "HOST", sources: ["rustscan"] });
        out.services.push({ host, port, protocol: "tcp", state: "OPEN", confidence: 0.5, sources: ["rustscan"] });
        out.records++;
      } else if (!/^(Starting|batch size|ulimit|Scanning|Completed|Open)/i.test(trimmed)) {
        out.warnings.push(`rustscan: skipped unrecognized line "${trimmed.slice(0, 80)}"`);
      }
    }
    // Dedupe services the two line shapes may both report.
    const seen = new Set<string>();
    out.services = out.services.filter((s) => {
      const key = `${s.host}|${s.port}|${s.protocol}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    applyNetworkChecks(out, this.tool, []);
    out.metrics = { records: out.records, services: out.services.length, findings: out.findings.length };
    return out;
  }
}

// ---------------------------------------------------------------------------
// Masscan JSON list output (§19)
// ---------------------------------------------------------------------------

export class MasscanParser implements NetworkParser {
  readonly tool = "masscan";

  parse(raw: string): ParsedNetwork {
    const out = emptyNetworkParsed();
    let doc: unknown;
    try { doc = JSON.parse(raw); } catch {
      out.warnings.push("masscan: output was not valid JSON — no records parsed");
      return out;
    }
    if (!Array.isArray(doc)) {
      out.warnings.push("masscan: output was not a JSON array — no records parsed");
      return out;
    }
    const seenAssets = new Set<string>();
    for (const entry of doc as Array<Record<string, unknown>>) {
      const ip = str(entry.ip);
      if (!ip) continue;
      if (!seenAssets.has(ip)) {
        seenAssets.add(ip);
        out.assets.push({ host: ip, ip, type: "HOST", sources: ["masscan"] });
      }
      for (const p of Array.isArray(entry.ports) ? entry.ports as Array<Record<string, unknown>> : []) {
        const port = num(p.port);
        if (port === undefined) continue;
        const svc = (p.service && typeof p.service === "object") ? p.service as Record<string, unknown> : {};
        out.services.push({
          host: ip, port, protocol: (str(p.proto) ?? "tcp").toLowerCase(),
          state: portState(str(p.status) ?? "open"),
          ...(str(svc.name) ? { name: str(svc.name) } : {}),
          ...(str(svc.banner) ? { banner: sanitizeBanner(str(svc.banner)) } : {}),
          confidence: 0.5,
          sources: ["masscan"],
        });
        out.records++;
      }
    }
    applyNetworkChecks(out, this.tool, []);
    out.metrics = { records: out.records, services: out.services.length, findings: out.findings.length };
    return out;
  }
}

// ---------------------------------------------------------------------------
// Netdiscover text table (§21): local ARP discovery — assets only
// ---------------------------------------------------------------------------

export class NetdiscoverParser implements NetworkParser {
  readonly tool = "netdiscover";

  parse(raw: string): ParsedNetwork {
    const out = emptyNetworkParsed();
    for (const line of raw.split(/\r?\n/)) {
      const m = line.match(/^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+/);
      if (!m) continue;
      out.assets.push({ host: m[1]!, ip: m[1]!, type: "HOST", sources: ["netdiscover"] });
      out.observations.push({ kind: "INFORMATIONAL", summary: `ARP: ${m[1]} at ${m[2]!.toLowerCase()}`, host: m[1]! });
      out.records++;
    }
    out.metrics = { records: out.records, hosts: out.assets.length };
    return out;
  }
}

// ---------------------------------------------------------------------------
// arp-scan: XML (--xml) or text lines (§22) — assets only
// ---------------------------------------------------------------------------

export class ArpScanParser implements NetworkParser {
  readonly tool = "arp-scan";

  parse(raw: string): ParsedNetwork {
    const out = emptyNetworkParsed();
    if (raw.trimStart().startsWith("<")) {
      const parsed = parseXmlLite(raw);
      if ("error" in parsed) {
        out.warnings.push(`arp-scan: XML rejected — ${parsed.error}`);
        return out;
      }
      const hostsNode = parsed.root.tag === "hosts" ? parsed.root : firstChild(parsed.root, "hosts");
      for (const hostNode of hostsNode ? childrenNamed(hostsNode, "host") : []) {
        const addrNodes = childrenNamed(hostNode, "address");
        const ip = addrNodes.find((a) => a.attrs.addrtype === "ipv4")?.text.trim();
        const mac = addrNodes.find((a) => a.attrs.addrtype === "mac")?.text.trim();
        if (!ip) continue;
        out.assets.push({ host: ip, ip, type: "HOST", sources: ["arp-scan"] });
        out.observations.push({ kind: "INFORMATIONAL", summary: `ARP: ${ip}${mac ? ` at ${mac.toLowerCase()}` : ""}`, host: ip });
        out.records++;
      }
    } else {
      for (const line of raw.split(/\r?\n/)) {
        const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b/);
        if (!m) continue;
        out.assets.push({ host: m[1]!, ip: m[1]!, type: "HOST", sources: ["arp-scan"] });
        out.observations.push({ kind: "INFORMATIONAL", summary: `ARP: ${m[1]} at ${m[2]!.toLowerCase()}`, host: m[1]! });
        out.records++;
      }
    }
    out.metrics = { records: out.records, hosts: out.assets.length };
    return out;
  }
}

// ---------------------------------------------------------------------------
// tshark -T json: OFFLINE capture analysis (§45)
// ---------------------------------------------------------------------------

export class TsharkParser implements NetworkParser {
  readonly tool = "tshark";

  parse(raw: string): ParsedNetwork {
    const out = emptyNetworkParsed();
    let doc: unknown;
    try { doc = JSON.parse(raw); } catch {
      out.warnings.push("tshark: output was not valid JSON — no packets parsed");
      return out;
    }
    if (!Array.isArray(doc)) {
      out.warnings.push("tshark: output was not a JSON array — no packets parsed");
      return out;
    }
    const protocols = new Map<string, number>();
    for (const pkt of doc as Array<Record<string, unknown>>) {
      const layers = ((pkt._source as Record<string, unknown> | undefined)?.layers ?? {}) as Record<string, Record<string, string>>;
      const protoNames = Object.keys(layers).filter((k) => k !== "frame");
      const top = protoNames[protoNames.length - 1] ?? "unknown";
      protocols.set(top, (protocols.get(top) ?? 0) + 1);
      const http = layers.http;
      const ip = layers.ip;
      const tcp = layers.tcp;
      if (http && ip) {
        const method = http["http.request.method"];
        const host = http["http.host"] ?? ip["ip.dst"];
        const uri = http["http.request.uri"] ?? "/";
        const status = http["http.response.code"];
        if (host && (method || status)) {
          out.transactions.push({
            method: method ?? "RESPONSE",
            url: `http://${host}${uri}`,
            host, path: uri,
            ...(status ? { statusCode: Number(status) || undefined } : {}),
            source: "tshark",
            ...(tcp?.["tcp.len"] ? { responseSize: Number(tcp["tcp.len"]) || undefined } : {}),
          });
        }
      }
      out.records++;
    }
    out.metrics = {
      records: out.records, packets: out.records, transactions: out.transactions.length,
      ...Object.fromEntries([...protocols.entries()].map(([k, v]) => [`proto_${k.replace(/[^a-z0-9]/gi, "_")}`, v])),
    };
    return out;
  }
}
