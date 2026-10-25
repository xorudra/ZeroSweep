import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolMetadata } from "../adapter/adapter.types";
import { ReconAdapterBase, TIMEOUT_FIELD, URLS_FIELD, type ReconPlanParts } from "../recon/recon-adapter.base";
import type { ReconParser } from "../recon/parsers-common";
import { ArjunParser, FeroxbusterParser, FfufParser, GobusterParser, WfuzzParser } from "./parsers-webdiscovery";
import { prioritizeParameterTargets } from "./classify";
import {
  defaultWordlistManager, wordlistContainerPath, type WordlistCategory, type WordlistManager, type WordlistProfile, type WordlistRecord,
} from "./wordlists";

/**
 * Web content / route / parameter discovery adapters (Prompt 6 §2–§7).
 * All five implement the SAME SecurityToolAdapter contract through the
 * Phase 5 ReconAdapterBase — no parallel execution framework. Every plan
 * is an executable + validated argument array; wordlists enter plans ONLY
 * as registered WordlistManager references (§10–§11); rates, concurrency,
 * depth and timeouts are clamped to per-adapter hard caps in code, so a
 * profile can lower them but never raise them (§14/§15). Content
 * discovery is intrusive-adjacent: defaults are conservative, and these
 * adapters only ever run inside the worker's authorization/scope/policy
 * gates against verified, in-scope targets.
 */

import type { AdapterInputField } from "../adapter/adapter.types";

export const WORDLIST_ID_FIELD: AdapterInputField = { name: "wordlistId", type: "string", description: "REGISTERED wordlist id (WordlistManager) — never a filesystem path (§11)" };
export const WORDLIST_PROFILE_FIELD: AdapterInputField = { name: "wordlistProfile", type: "string", enumValues: ["SMALL", "STANDARD", "COMPREHENSIVE"], description: "Wordlist profile (§12); COMPREHENSIVE is never auto-selected by templates" };
export const RATE_FIELD: AdapterInputField = { name: "rateLimit", type: "number", min: 1, max: 50, description: "Requests-per-second ceiling, clamped to the adapter hard cap (§15)" };
export const CONCURRENCY_FIELD: AdapterInputField = { name: "concurrency", type: "number", min: 1, max: 20, description: "Parallel workers, clamped to the adapter hard cap (§15)" };
export const TECHNOLOGIES_FIELD: AdapterInputField = { name: "technologies", type: "string[]", description: "Technology names detected by earlier stages — HINTS for technology-aware wordlists (§13)" };

export const DEFAULT_RATE_LIMIT = 10;
export const MAX_RATE_LIMIT = 50;
export const DEFAULT_CONCURRENCY = 10;
export const MAX_CONCURRENCY = 20;

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
    defaultTimeoutSeconds: 600,
    maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 600 },
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD],
    ...partial,
  };
}

export function startUrlOf(target: AdapterTarget): string {
  return target.value.includes("://") ? target.value : `https://${target.host}/`;
}

/** Base URL a discovery plan fuzzes: the first live URL handed down by
 *  earlier stages, else the target's own start URL. Always ends with "/". */
export function baseUrlOf(target: AdapterTarget, config: Record<string, unknown>): string {
  const urls = Array.isArray(config.urls) && config.urls.length > 0 ? (config.urls as string[]) : [startUrlOf(target)];
  const first = urls[0]!;
  return first.endsWith("/") ? first : `${first}/`;
}

export abstract class WebDiscoveryAdapterBase extends ReconAdapterBase {
  protected readonly wordlists: WordlistManager = defaultWordlistManager;
  /** Wordlist category this adapter draws its primary list from. */
  protected abstract readonly wordlistCategory: WordlistCategory;
  protected readonly defaultProfile: WordlistProfile = "SMALL";

  /** Wordlist references are validated at configuration time (§11): an
   *  unregistered id — or anything path-shaped — fails before any plan
   *  exists. */
  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    if (config.wordlistId !== undefined) {
      try {
        this.wordlists.resolve(config.wordlistId as string);
      } catch (e) {
        throw new AdapterConfigurationError(e instanceof Error ? e.message : "invalid wordlistId");
      }
    }
  }

  protected profileOf(config: Record<string, unknown>): WordlistProfile {
    const p = config.wordlistProfile;
    return p === "STANDARD" || p === "COMPREHENSIVE" ? p : this.defaultProfile;
  }

  /** The registered wordlist a plan will reference: an explicit registered
   *  id wins; otherwise the profile list for this adapter's category, with
   *  technology-specific lists surfaced as additional references (§13). */
  /** Public view of the wordlist a plan will use — observability for the
   *  worker/API without exposing plan internals. */
  wordlistPlan(config: Record<string, unknown>): { primary: WordlistRecord; additional: WordlistRecord[]; containerPath: string } {
    return this.resolveWordlist(config);
  }

  protected resolveWordlist(config: Record<string, unknown>): { primary: WordlistRecord; additional: WordlistRecord[]; containerPath: string } {
    if (typeof config.wordlistId === "string") {
      const primary = this.wordlists.resolve(config.wordlistId);
      return { primary, additional: [], containerPath: wordlistContainerPath(primary) };
    }
    const technologies = Array.isArray(config.technologies) ? (config.technologies as string[]) : [];
    const { primary, additional } = this.wordlists.resolveForDiscovery({
      category: this.wordlistCategory, profile: this.profileOf(config), technologies,
    });
    return { primary, additional, containerPath: wordlistContainerPath(primary) };
  }

  protected rateOf(config: Record<string, unknown>): number {
    const v = config.rateLimit;
    return typeof v === "number" ? Math.min(MAX_RATE_LIMIT, Math.max(1, Math.floor(v))) : DEFAULT_RATE_LIMIT;
  }
  protected concurrencyOf(config: Record<string, unknown>): number {
    const v = config.concurrency;
    return typeof v === "number" ? Math.min(MAX_CONCURRENCY, Math.max(1, Math.floor(v))) : DEFAULT_CONCURRENCY;
  }
}

export class FfufAdapter extends WebDiscoveryAdapterBase {
  readonly executable = "ffuf";
  readonly containerImage = "ffuf/ffuf";
  readonly versionArgs = ["-V"];
  protected readonly parser: ReconParser = new FfufParser();
  protected readonly wordlistCategory: WordlistCategory = "COMMON_DIRECTORIES";
  readonly metadata = meta({
    id: "ffuf", slug: "ffuf", name: "ffuf",
    description: "ffuf: fast content discovery (directories, files, routes) with a registered wordlist; vhost discovery only when separately enabled (§3).",
    homepage: "https://github.com/ffuf/ffuf",
    category: "WEB", riskLevel: "MODERATE",
    capabilities: ["CONTENT_DISCOVERY", "DIRECTORY_DISCOVERY", "FILE_DISCOVERY", "VHOST_DISCOVERY"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    inputSchema: [
      URLS_FIELD, WORDLIST_ID_FIELD, WORDLIST_PROFILE_FIELD, TECHNOLOGIES_FIELD, RATE_FIELD, CONCURRENCY_FIELD,
      { name: "vhostMode", type: "boolean", description: "Vhost discovery (§3): separately enabled, off by default; runs against the target host with a Host-header fuzz" },
      TIMEOUT_FIELD,
    ],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const { containerPath } = this.resolveWordlist(config);
    const rate = this.rateOf(config);
    const threads = this.concurrencyOf(config);
    if (config.vhostMode === true) {
      // Vhost mode (§3): the FUZZ keyword moves into the Host header; the
      // request target itself stays the in-scope origin.
      const origin = new URL(baseUrlOf(target, config)).origin;
      return {
        args: [
          "-w", containerPath, "-u", origin, "-H", `Host: FUZZ.${target.host}`,
          "-of", "json", "-o", "/dev/stdout", "-s",
          "-rate", String(rate), "-t", String(threads), "-timeout", "10",
        ],
        outputFiles: [],
      };
    }
    return {
      args: [
        "-w", containerPath, "-u", `${baseUrlOf(target, config)}FUZZ`,
        "-of", "json", "-o", "/dev/stdout", "-s",
        "-rate", String(rate), "-t", String(threads), "-timeout", "10",
        // Deliberately absent: -r (redirect following — destinations are
        // recorded, never chased, §20) and any user-defined match/filter
        // or recursion flags. Default ffuf status matching applies.
      ],
    };
  }
}

export class FeroxbusterAdapter extends WebDiscoveryAdapterBase {
  readonly executable = "feroxbuster";
  readonly containerImage = "epi052/feroxbuster";
  readonly versionArgs = ["--version"];
  protected readonly parser: ReconParser = new FeroxbusterParser();
  protected readonly wordlistCategory: WordlistCategory = "COMMON_DIRECTORIES";
  protected override readonly defaultProfile: WordlistProfile = "STANDARD";
  /** Recursion hard cap (§4): profiles may lower depth, never raise it. */
  static readonly MAX_DEPTH = 4;
  readonly metadata = meta({
    id: "feroxbuster", slug: "feroxbuster", name: "Feroxbuster",
    description: "Feroxbuster: recursive content discovery with hard depth / rate / request limits and scope enforcement (§4).",
    homepage: "https://github.com/epi052/feroxbuster",
    category: "WEB", riskLevel: "MODERATE",
    capabilities: ["CONTENT_DISCOVERY", "DIRECTORY_DISCOVERY", "RECURSIVE_CONTENT_DISCOVERY"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    defaultTimeoutSeconds: 900,
    maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 900 },
    inputSchema: [
      URLS_FIELD, WORDLIST_ID_FIELD, WORDLIST_PROFILE_FIELD, TECHNOLOGIES_FIELD, RATE_FIELD, CONCURRENCY_FIELD,
      { name: "depth", type: "number", min: 1, max: FeroxbusterAdapter.MAX_DEPTH, description: "Recursion depth, hard-capped at 4 by the adapter (§4)" },
      TIMEOUT_FIELD,
    ],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const { containerPath } = this.resolveWordlist(config);
    const depth = typeof config.depth === "number" ? Math.min(FeroxbusterAdapter.MAX_DEPTH, Math.max(1, Math.floor(config.depth))) : 2;
    return {
      args: [
        "-u", baseUrlOf(target, config),
        "-w", containerPath,
        "--json", "--output", "/dev/stdout", "--silent",
        "--depth", String(depth),
        "--threads", String(this.concurrencyOf(config)),
        "--rate-limit", String(this.rateOf(config)),
        "--timeout", "10",
        // No --extract-links crawling of response bodies and no redirect
        // following: scope stays with the plan (§4/§20).
      ],
    };
  }
}

export class GobusterAdapter extends WebDiscoveryAdapterBase {
  readonly executable = "gobuster";
  readonly containerImage = "zerosweep/gobuster"; // platform image built from the official release
  readonly versionArgs = ["version"];
  protected readonly parser: ReconParser = new GobusterParser();
  protected readonly wordlistCategory: WordlistCategory = "COMMON_DIRECTORIES";
  private lastBaseUrl: string | undefined;
  readonly metadata = meta({
    id: "gobuster", slug: "gobuster", name: "Gobuster",
    description: "Gobuster (dir mode only — the explicitly approved mode, §5): directory and file discovery with a registered wordlist. DNS/vhost modes are not exposed; DNS discovery belongs to the recon pipeline.",
    homepage: "https://github.com/OJ/gobuster",
    category: "WEB", riskLevel: "MODERATE",
    // CONTENT_DISCOVERY is included so the content-discovery stage (which
    // selects by that capability) picks Gobuster up alongside ffuf et al.;
    // its specialities remain directory + file discovery (§5).
    capabilities: ["CONTENT_DISCOVERY", "DIRECTORY_DISCOVERY", "FILE_DISCOVERY"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["TEXT"],
    inputSchema: [URLS_FIELD, WORDLIST_ID_FIELD, WORDLIST_PROFILE_FIELD, TECHNOLOGIES_FIELD, CONCURRENCY_FIELD, TIMEOUT_FIELD],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const { containerPath } = this.resolveWordlist(config);
    const base = baseUrlOf(target, config);
    this.lastBaseUrl = base;
    return {
      args: [
        "dir", // the ONLY mode this adapter exposes (§5) — no dns/vhost/s3 modes, no arbitrary flags
        "-u", base,
        "-w", containerPath,
        "-q", // quiet: results only, no banner/progress noise in the artifact
        "-t", String(this.concurrencyOf(config)),
        "--delay", "100ms", // conservative pacing (§15)
        "--timeout", "10s",
        // No -r: redirects are recorded by the parser, never followed (§20).
      ],
    };
  }
  /** Gobuster reports paths; its parser needs the plan's base URL. */
  override async parse(raw: string): Promise<unknown> {
    const parsed = new GobusterParser(this.lastBaseUrl).parse(raw && raw.length > 0 ? raw : this.lastRaw);
    this.lastWarnings = parsed.warnings;
    return parsed;
  }
}

export class WfuzzAdapter extends WebDiscoveryAdapterBase {
  readonly executable = "wfuzz";
  readonly containerImage = "zerosweep/wfuzz"; // platform image built from the official release
  readonly versionArgs = ["--version"];
  protected readonly parser: ReconParser = new WfuzzParser();
  protected readonly wordlistCategory: WordlistCategory = "COMMON_DIRECTORIES";
  readonly metadata = meta({
    id: "wfuzz", slug: "wfuzz", name: "Wfuzz",
    description: "Wfuzz in CONTROLLED mode (§6): only the two predefined platform templates (CONTENT, PARAMETER) exist — arbitrary payload construction and user-supplied arguments are impossible through this adapter.",
    homepage: "https://github.com/xmendez/wfuzz",
    category: "WEB", riskLevel: "MODERATE",
    capabilities: ["CONTENT_DISCOVERY", "PARAMETER_DISCOVERY"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    inputSchema: [
      URLS_FIELD, WORDLIST_ID_FIELD, WORDLIST_PROFILE_FIELD, TECHNOLOGIES_FIELD, CONCURRENCY_FIELD,
      { name: "template", type: "string", enumValues: ["CONTENT", "PARAMETER"], description: "Predefined safe discovery template (§6/§29) — the only wfuzz modes that exist" },
      TIMEOUT_FIELD,
    ],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const template = config.template === "PARAMETER" ? "PARAMETER" : "CONTENT";
    const threads = Math.min(10, this.concurrencyOf(config));
    if (template === "PARAMETER") {
      // Predefined parameter-discovery template (§29): the platform's
      // registered PARAMETER_NAMES list is fuzzed as query keys against
      // ONE eligible endpoint; values are a fixed benign marker.
      const paramList = typeof config.wordlistId === "string"
        ? this.wordlists.resolve(config.wordlistId)
        : this.wordlists.forProfile("PARAMETER_NAMES", this.profileOf(config));
      const base = baseUrlOf(target, config);
      const separator = base.includes("?") ? "&" : "?";
      return {
        args: [
          "-z", `file,${wordlistContainerPath(paramList)}`,
          "--hc", "404,400",
          "-t", String(threads),
          "-f", "/dev/stdout,json",
          `${base}${separator}FUZZ=zerosweep`,
        ],
      };
    }
    const { containerPath } = this.resolveWordlist(config);
    return {
      args: [
        "-z", `file,${containerPath}`,
        "--hc", "404",
        "-t", String(threads),
        "-f", "/dev/stdout,json",
        `${baseUrlOf(target, config)}FUZZ`,
      ],
    };
  }
}

export class ArjunAdapter extends WebDiscoveryAdapterBase {
  readonly executable = "arjun";
  readonly containerImage = "zerosweep/arjun"; // platform image built from the official release
  readonly versionArgs: string[] = [];
  protected readonly parser: ReconParser = new ArjunParser();
  protected readonly wordlistCategory: WordlistCategory = "PARAMETER_NAMES";
  readonly metadata = meta({
    id: "arjun", slug: "arjun", name: "Arjun",
    description: "Arjun: HTTP parameter-name discovery (§7). Fed only prioritized, in-scope, eligible endpoints (§28); stores parameter names, never values.",
    homepage: "https://github.com/s0md3v/Arjun",
    category: "WEB", riskLevel: "LOW",
    capabilities: ["PARAMETER_DISCOVERY"],
    supportedTargetTypes: ["WEB_APPLICATION", "API"],
    supportedOutputFormats: ["JSON"],
    defaultTimeoutSeconds: 300,
    maxTimeoutSeconds: 900,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 300 },
    inputSchema: [
      URLS_FIELD,
      { name: "concurrency", type: "number", min: 1, max: 10, description: "Threads, hard-capped at 10 (§28 strict budgets)" },
      TIMEOUT_FIELD,
    ],
  });
  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    // §28: never run blindly against every historical URL — pick the
    // highest-priority eligible endpoint (API-looking / GET / live first).
    const urls = Array.isArray(config.urls) && config.urls.length > 0 ? (config.urls as string[]) : [startUrlOf(target)];
    const prioritized = prioritizeParameterTargets(urls.map((url) => ({ url })), 1);
    const url = prioritized[0]?.url ?? urls[0]!;
    const threads = typeof config.concurrency === "number" ? Math.min(10, Math.max(1, Math.floor(config.concurrency))) : 5;
    return {
      args: [
        "-u", url,
        "-oJ", "/dev/stdout", // JSON output to stdout artifact
        "-t", String(threads),
        "--stable", // stable mode: fewer, deliberate requests (§15/§28)
      ],
    };
  }
}
