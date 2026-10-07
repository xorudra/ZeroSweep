import { canonicalizeHostname } from "./normalize";
import {
  emptyParsed, parseHostLines, parseJsonLines, str, strArr,
  type ParsedRecon, type ReconParser,
} from "./parsers-common";

/**
 * Discovery parsers (Prompt 5 §36): Subfinder, Amass, Assetfinder,
 * Findomain, dnsx. All normalize into the SAME asset model — tool-specific
 * output shapes never leak past this file (§7).
 */

export class SubfinderParser implements ReconParser {
  readonly tool = "subfinder";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    // subfinder -json emits JSONL {"host","input","source"}; without -json it
    // emits plain hosts. Accept both.
    if (raw.includes("{")) {
      const { records, warnings } = parseJsonLines(raw, this.tool);
      out.warnings.push(...warnings);
      for (const rec of records) {
        const host = canonicalizeHostname(str(rec.host) ?? str(rec.hostname) ?? "");
        if (!host) { out.warnings.push("subfinder: record without a valid host skipped"); continue; }
        out.records++;
        out.assets.push({ host, type: "SUBDOMAIN", sources: ["subfinder"] });
      }
    } else {
      const { hosts, warnings } = parseHostLines(raw, this.tool);
      out.warnings.push(...warnings);
      for (const host of hosts) { out.records++; out.assets.push({ host, type: "SUBDOMAIN", sources: ["subfinder"] }); }
    }
    out.metrics.records = out.records;
    return out;
  }
}

export class AmassParser implements ReconParser {
  readonly tool = "amass";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    if (raw.includes("{")) {
      const { records, warnings } = parseJsonLines(raw, this.tool);
      out.warnings.push(...warnings);
      for (const rec of records) {
        const host = canonicalizeHostname(str(rec.name) ?? str(rec.host) ?? "");
        if (!host) { out.warnings.push("amass: record without a valid name skipped"); continue; }
        out.records++;
        const addresses = Array.isArray(rec.addresses) ? rec.addresses : [];
        const ips: string[] = [];
        for (const a of addresses) {
          if (a && typeof a === "object" && typeof (a as { ip?: unknown }).ip === "string") ips.push((a as { ip: string }).ip);
        }
        const aRecs = ips.filter((ip) => ip.includes("."));
        const aaaaRecs = ips.filter((ip) => ip.includes(":"));
        const dns = [
          ...(aRecs.length ? [{ type: "A", values: aRecs }] : []),
          ...(aaaaRecs.length ? [{ type: "AAAA", values: aaaaRecs }] : []),
        ];
        out.assets.push({
          host, type: "SUBDOMAIN", sources: ["amass"],
          ...(ips[0] ? { ip: ips[0] } : {}),
          ...(dns.length ? { dnsRecords: dns } : {}),
        });
      }
    } else {
      const { hosts, warnings } = parseHostLines(raw, this.tool);
      out.warnings.push(...warnings);
      for (const host of hosts) { out.records++; out.assets.push({ host, type: "SUBDOMAIN", sources: ["amass"] }); }
    }
    out.metrics.records = out.records;
    return out;
  }
}

export class AssetfinderParser implements ReconParser {
  readonly tool = "assetfinder";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const { hosts, warnings } = parseHostLines(raw, this.tool);
    out.warnings.push(...warnings);
    for (const host of hosts) { out.records++; out.assets.push({ host, type: "SUBDOMAIN", sources: ["assetfinder"] }); }
    out.metrics.records = out.records;
    return out;
  }
}

export class FindomainParser implements ReconParser {
  readonly tool = "findomain";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const { hosts, warnings } = parseHostLines(raw, this.tool);
    out.warnings.push(...warnings);
    for (const host of hosts) { out.records++; out.assets.push({ host, type: "SUBDOMAIN", sources: ["findomain"] }); }
    out.metrics.records = out.records;
    return out;
  }
}

/** Label prefix of the wildcard-DNS probe host the dnsx adapter injects
 *  (Prompt 5 §29): a name that should never exist. If it resolves, the zone
 *  answers everything and its IP set marks wildcard-suspect hosts. */
export const WILDCARD_PROBE_PREFIX = "nxprobe-";

export class DnsxParser implements ReconParser {
  readonly tool = "dnsx";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const { records, warnings } = parseJsonLines(raw, this.tool);
    out.warnings.push(...warnings);
    const wildcardIps = new Set<string>();
    for (const rec of records) {
      const hostRaw = str(rec.host) ?? "";
      const a = strArr(rec.a);
      const aaaa = strArr(rec.aaaa);
      if (hostRaw.startsWith(WILDCARD_PROBE_PREFIX)) {
        for (const ip of [...a, ...aaaa]) wildcardIps.add(ip);
        continue; // the probe itself is never an asset
      }
      const host = canonicalizeHostname(hostRaw);
      if (!host) { out.warnings.push("dnsx: record without a valid host skipped"); continue; }
      out.records++;
      const dns = [
        ...(a.length ? [{ type: "A", values: a }] : []),
        ...(aaaa.length ? [{ type: "AAAA", values: aaaa }] : []),
        ...(strArr(rec.cname).length ? [{ type: "CNAME", values: strArr(rec.cname) }] : []),
        ...(strArr(rec.ns).length ? [{ type: "NS", values: strArr(rec.ns) }] : []),
        ...(strArr(rec.mx).length ? [{ type: "MX", values: strArr(rec.mx) }] : []),
        ...(strArr(rec.txt).length ? [{ type: "TXT", values: strArr(rec.txt) }] : []),
        ...(str(rec.soa) ? [{ type: "SOA", values: [str(rec.soa)!] }] : []),
      ];
      const allIps = [...a, ...aaaa];
      out.assets.push({
        host, type: "HOST", sources: ["dnsx"],
        ...(a[0] ?? aaaa[0] ? { ip: (a[0] ?? aaaa[0])! } : {}),
        ...(dns.length ? { dnsRecords: dns } : {}),
        ...(allIps.length > 0 && allIps.every((ip) => wildcardIps.has(ip)) ? { wildcardSuspect: true } : {}),
      });
    }
    if (wildcardIps.size > 0) {
      out.wildcardIpSet = [...wildcardIps];
      out.metrics.wildcardDetected = 1;
    }
    out.metrics.records = out.records;
    return out;
  }
}
