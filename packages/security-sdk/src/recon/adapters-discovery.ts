import { createHash } from "node:crypto";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolMetadata } from "../adapter/adapter.types";
import { ReconAdapterBase, HOSTS_FIELD, TIMEOUT_FIELD, type ReconPlanParts } from "./recon-adapter.base";
import type { ToolRunner } from "./runner";
import { AmassParser, AssetfinderParser, DnsxParser, FindomainParser, SubfinderParser, WILDCARD_PROBE_PREFIX } from "./parsers-discovery";
import type { ReconParser } from "./parsers-common";

/**
 * Subdomain / DNS discovery adapters (Prompt 5 §5–§9). All five normalize
 * into the same asset model via their dedicated parsers; none of them can
 * create findings, and discovered hostnames are scope-checked downstream
 * before any active tool touches them (§23).
 */

function meta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "riskLevel" | "capabilities" | "supportedTargetTypes" | "supportedOutputFormats">): ToolMetadata {
  return {
    category: "RECON",
    adapterVersion: "1.0.0",
    licenseType: "OPEN_SOURCE",
    executionMode: "CONTAINER",
    requiresCredentials: [],
    requiresApproval: false,
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 300,
    maxTimeoutSeconds: 900,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 300 },
    inputSchema: [TIMEOUT_FIELD],
    ...partial,
  };
}

export class SubfinderAdapter extends ReconAdapterBase {
  readonly executable = "subfinder";
  readonly containerImage = "projectdiscovery/subfinder";
  readonly versionArgs = ["-version"];
  protected readonly parser: ReconParser = new SubfinderParser();
  readonly metadata = meta({
    id: "subfinder", slug: "subfinder", name: "Subfinder",
    description: "Passive subdomain enumeration from public sources (ProjectDiscovery).",
    homepage: "https://github.com/projectdiscovery/subfinder",
    riskLevel: "LOW", // Prompt 5 §5
    capabilities: ["SUBDOMAIN_DISCOVERY"],
    supportedTargetTypes: ["DOMAIN"],
    supportedOutputFormats: ["JSONL"],
  });
  protected override planNetworkPolicy() { return "INTERNET_READ_ONLY" as const; }
  protected planFor(target: AdapterTarget): ReconPlanParts {
    // Official flags (ProjectDiscovery docs): -d domain, -json JSONL output,
    // -silent banner-free stdout. Sources are passive; the tool never
    // resolves or probes the target itself in this configuration.
    return { args: ["-d", target.host, "-json", "-silent"] };
  }
}

export class AmassAdapter extends ReconAdapterBase {
  readonly executable = "amass";
  readonly containerImage = "caffix/amass";
  readonly versionArgs = ["-version"];
  protected readonly parser: ReconParser = new AmassParser();
  readonly metadata = meta({
    id: "amass", slug: "amass", name: "Amass",
    description: "OWASP Amass passive enumeration: subdomains + DNS/address data from OSINT sources.",
    homepage: "https://github.com/owasp-amass/amass",
    riskLevel: "PASSIVE",
    capabilities: ["SUBDOMAIN_DISCOVERY", "DNS_DISCOVERY"],
    supportedTargetTypes: ["DOMAIN"],
    supportedOutputFormats: ["JSONL", "TEXT"],
    defaultTimeoutSeconds: 600,
    maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "1Gi", timeoutSeconds: 600 },
  });
  protected override planNetworkPolicy() { return "INTERNET_READ_ONLY" as const; }
  protected planFor(target: AdapterTarget): ReconPlanParts {
    // Passive mode ONLY (§6): no active DNS brute forcing configuration is
    // enabled by this adapter — `enum -passive` queries third-party sources.
    return { args: ["enum", "-passive", "-d", target.host, "-nocolor"] };
  }
}

export class AssetfinderAdapter extends ReconAdapterBase {
  readonly executable = "assetfinder";
  readonly containerImage = "zerosweep/assetfinder"; // platform image built from the official release (§3)
  readonly versionArgs: string[] = [];
  protected readonly parser: ReconParser = new AssetfinderParser();
  readonly metadata = meta({
    id: "assetfinder", slug: "assetfinder", name: "Assetfinder",
    description: "tomnomnom assetfinder: fast subdomain discovery from public indexes.",
    homepage: "https://github.com/tomnomnom/assetfinder",
    riskLevel: "PASSIVE",
    capabilities: ["SUBDOMAIN_DISCOVERY"],
    supportedTargetTypes: ["DOMAIN"],
    supportedOutputFormats: ["TEXT"],
  });
  protected override planNetworkPolicy() { return "INTERNET_READ_ONLY" as const; }
  protected planFor(target: AdapterTarget): ReconPlanParts {
    return { args: ["--subs-only", target.host] };
  }
}

export class FindomainAdapter extends ReconAdapterBase {
  readonly executable = "findomain";
  readonly containerImage = "zerosweep/findomain"; // platform image built from the official release (§3)
  readonly versionArgs = ["--version"];
  protected readonly parser: ReconParser = new FindomainParser();
  readonly metadata = meta({
    id: "findomain", slug: "findomain", name: "Findomain",
    description: "Findomain: cross-platform subdomain enumeration via certificate/search APIs.",
    homepage: "https://github.com/Findomain/Findomain",
    riskLevel: "PASSIVE",
    capabilities: ["SUBDOMAIN_DISCOVERY"],
    supportedTargetTypes: ["DOMAIN"],
    supportedOutputFormats: ["TEXT"],
  });
  protected override planNetworkPolicy() { return "INTERNET_READ_ONLY" as const; }
  protected planFor(target: AdapterTarget): ReconPlanParts {
    // -q (quiet) prints one hostname per line — machine-readable stdout.
    return { args: ["-t", target.host, "-q"] };
  }
}

export class DnsxAdapter extends ReconAdapterBase {
  readonly executable = "dnsx";
  readonly containerImage = "projectdiscovery/dnsx";
  readonly versionArgs = ["-version"];
  protected readonly parser: ReconParser = new DnsxParser();
  readonly metadata = meta({
    id: "dnsx", slug: "dnsx", name: "dnsx",
    description: "ProjectDiscovery dnsx: DNS resolution + record collection for authorized hostnames.",
    homepage: "https://github.com/projectdiscovery/dnsx",
    riskLevel: "LOW",
    capabilities: ["DNS_RESOLUTION", "DNS_DISCOVERY"],
    supportedTargetTypes: ["DOMAIN"],
    supportedOutputFormats: ["JSONL"],
    inputSchema: [HOSTS_FIELD, TIMEOUT_FIELD],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    // Input is the authorized host list from previous stages (§9) delivered
    // as data-only stdin — plus one wildcard-probe label (§29): a
    // deterministic non-existent name whose resolution proves wildcard DNS.
    const hosts = Array.isArray(config.hosts) && config.hosts.length > 0 ? (config.hosts as string[]) : [target.host];
    const probe = `${WILDCARD_PROBE_PREFIX}${createHash("sha256").update(target.host).digest("hex").slice(0, 8)}.${target.host}`;
    return {
      args: ["-json", "-silent", "-a", "-aaaa", "-cname", "-ns", "-mx", "-txt", "-soa"],
      stdin: [...hosts, probe].join("\n"),
    };
  }
}
