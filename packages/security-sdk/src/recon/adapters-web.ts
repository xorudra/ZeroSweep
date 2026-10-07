import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolMetadata } from "../adapter/adapter.types";
import { ReconAdapterBase, HOSTS_FIELD, TIMEOUT_FIELD, URLS_FIELD, type ReconPlanParts } from "./recon-adapter.base";
import { GauParser, HttpxParser, KatanaParser, WaybackurlsParser, WhatWebParser } from "./parsers-web";
import type { ReconParser } from "./parsers-common";

/**
 * Web-surface adapters (Prompt 5 §10–§14): httpx probing, WhatWeb
 * fingerprinting, historical URL discovery (gau / waybackurls) and the
 * conservative Katana crawl. Everything they emit is inventory metadata —
 * HTTP statuses and technologies are never findings (§47).
 */

function meta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "category" | "riskLevel" | "capabilities" | "supportedTargetTypes" | "supportedOutputFormats">): ToolMetadata {
  return {
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

function startUrl(target: AdapterTarget): string {
  return target.value.includes("://") ? target.value : `https://${target.host}/`;
}

export class HttpxAdapter extends ReconAdapterBase {
  readonly executable = "httpx";
  readonly containerImage = "projectdiscovery/httpx";
  readonly versionArgs = ["-version"];
  protected readonly parser: ReconParser = new HttpxParser();
  readonly metadata = meta({
    id: "httpx", slug: "httpx", name: "httpx",
    description: "ProjectDiscovery httpx: HTTP probing with status, title, server, tech and TLS metadata.",
    homepage: "https://github.com/projectdiscovery/httpx",
    category: "RECON", riskLevel: "LOW",
    capabilities: ["HTTP_PROBING", "TECHNOLOGY_DETECTION"],
    supportedTargetTypes: ["DOMAIN", "WEB_APPLICATION", "IP_ADDRESS"],
    supportedOutputFormats: ["JSONL"],
    defaultTimeoutSeconds: 600,
    maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 600 },
    inputSchema: [HOSTS_FIELD, TIMEOUT_FIELD],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    // Input hosts arrive as data-only stdin. NO redirect following flags:
    // redirect targets are recorded, never chased across scope (§30).
    // Conservative rate/concurrency (§27): 25 threads, 50 req/s ceiling.
    const hosts = Array.isArray(config.hosts) && config.hosts.length > 0 ? (config.hosts as string[]) : [target.host];
    return {
      args: ["-json", "-silent", "-title", "-status-code", "-content-type", "-web-server", "-tech-detect", "-tls-grab", "-timeout", "10", "-threads", "25", "-rate-limit", "50"],
      stdin: hosts.join("\n"),
    };
  }
}

export class WhatWebAdapter extends ReconAdapterBase {
  readonly executable = "whatweb";
  readonly containerImage = "dsrclone/whatweb"; // platform image built from the official release (§3)
  readonly versionArgs = ["--version"];
  protected readonly parser: ReconParser = new WhatWebParser();
  readonly metadata = meta({
    id: "whatweb", slug: "whatweb", name: "WhatWeb",
    description: "WhatWeb: web technology fingerprinting (server, CMS, frameworks, libraries, analytics).",
    homepage: "https://github.com/urbanadventurer/WhatWeb",
    category: "WEB", riskLevel: "LOW",
    capabilities: ["TECHNOLOGY_DETECTION"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    // Aggression fixed at 1 (passive fingerprinting of the landing page) —
    // deliberately NOT configurable upward by profiles (§11).
    const urls = Array.isArray(config.urls) && config.urls.length > 0 ? (config.urls as string[]) : [startUrl(target)];
    return { args: ["--no-errors", "-a", "1", "--log-json", "/dev/stdout", ...urls] };
  }
}

export class GauAdapter extends ReconAdapterBase {
  readonly executable = "gau";
  readonly containerImage = "dsrclone/gau"; // platform image built from the official release (§3)
  readonly versionArgs: string[] = [];
  protected readonly parser: ReconParser = new GauParser();
  readonly metadata = meta({
    id: "gau", slug: "gau", name: "gau (getallurls)",
    description: "gau: historical/known URL discovery from web archives and indexes (passive).",
    homepage: "https://github.com/lc/gau",
    category: "RECON", riskLevel: "PASSIVE",
    capabilities: ["URL_DISCOVERY", "HISTORICAL_URL_DISCOVERY"],
    supportedTargetTypes: ["DOMAIN"],
    supportedOutputFormats: ["TEXT"],
  });
  protected override planNetworkPolicy() { return "INTERNET_READ_ONLY" as const; }
  protected planFor(target: AdapterTarget): ReconPlanParts {
    // Queries third-party archives only — the target is never contacted,
    // and returned URLs are scope-checked before any later stage (§12).
    return { args: [target.host, "--threads", "5"] };
  }
}

export class WaybackurlsAdapter extends ReconAdapterBase {
  readonly executable = "waybackurls";
  readonly containerImage = "dsrclone/waybackurls"; // platform image built from the official release (§3)
  readonly versionArgs: string[] = [];
  protected readonly parser: ReconParser = new WaybackurlsParser();
  readonly metadata = meta({
    id: "waybackurls", slug: "waybackurls", name: "Waybackurls",
    description: "tomnomnom waybackurls: archived URL discovery from the Wayback Machine (passive).",
    homepage: "https://github.com/tomnomnom/waybackurls",
    category: "RECON", riskLevel: "PASSIVE",
    capabilities: ["URL_DISCOVERY", "HISTORICAL_URL_DISCOVERY"],
    supportedTargetTypes: ["DOMAIN"],
    supportedOutputFormats: ["TEXT"],
  });
  protected override planNetworkPolicy() { return "INTERNET_READ_ONLY" as const; }
  protected planFor(target: AdapterTarget): ReconPlanParts {
    // waybackurls reads domains from stdin (official usage) — data only.
    // Historical discovery never fetches the URLs themselves (§13).
    return { args: [], stdin: `${target.host}\n` };
  }
}

export class KatanaAdapter extends ReconAdapterBase {
  readonly executable = "katana";
  readonly containerImage = "projectdiscovery/katana";
  readonly versionArgs = ["-version"];
  protected readonly parser: ReconParser = new KatanaParser();
  readonly metadata = meta({
    id: "katana", slug: "katana", name: "Katana",
    description: "ProjectDiscovery Katana: scoped, rate-limited web crawling for endpoint inventory.",
    homepage: "https://github.com/projectdiscovery/katana",
    category: "WEB",
    // §14: LOW under the conservative configuration this adapter enforces
    // (depth ≤ 3, field-scope locked to the root domain, no form filling).
    riskLevel: "LOW",
    capabilities: ["WEB_CRAWLING", "URL_DISCOVERY", "ENDPOINT_DISCOVERY"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["JSONL"],
    defaultTimeoutSeconds: 900,
    maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "1Gi", timeoutSeconds: 900 },
    inputSchema: [
      URLS_FIELD,
      { name: "depth", type: "number", min: 1, max: 3, description: "Crawl depth, hard-capped at 3 by the adapter (§14)" },
      TIMEOUT_FIELD,
    ],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const urls = Array.isArray(config.urls) && config.urls.length > 0 ? (config.urls as string[]) : [startUrl(target)];
    const depth = typeof config.depth === "number" ? Math.min(3, Math.max(1, Math.floor(config.depth))) : 2;
    return {
      args: [
        "-u", urls[0]!,
        "-jsonl", "-silent",
        "-d", String(depth),
        "-jc", // crawl endpoints referenced from JavaScript files
        "-timeout", "10",
        "-c", "10", // concurrency ceiling (§14/§27)
        "-rl", "50", // request-rate ceiling
        "-mrs", "1048576", // 1 MiB response-size ceiling
        "-fs", "rdn", // field scope: root domain only — crawl never leaves scope
        // Deliberately absent: -aff/-automatic-form-fill and any form or
        // fuzzing flags. Katana form submission is unsafe behaviour (§14).
      ],
    };
  }
}
