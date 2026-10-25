import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { AdapterInputField, ToolMetadata } from "../adapter/adapter.types";
import { HOSTS_FIELD, TIMEOUT_FIELD, type ReconPlanParts } from "../recon/recon-adapter.base";
import { clampMasscanLimits, clampNetworkBudget } from "./budget";
import { isIpLiteral, parseCidr } from "./cidr";
import { NetworkAdapterBase } from "./network-adapter.base";
import {
  ArpScanParser, MasscanParser, NaabuParser, NetdiscoverParser, NmapParser,
  RustScanParser, TsharkParser, type NetworkParser,
} from "./parsers-network";
import { portProfileById, portSpecForProfile, validateCustomPorts, DEFAULT_PORT_PROFILE_ID } from "./port-profiles";
import { nmapScriptPolicy, NSE_POLICY_SNAPSHOT } from "./script-policy";

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
    defaultTimeoutSeconds: 900,
    maxTimeoutSeconds: 3600,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 900 },
    ...partial,
  };
}

const HOSTNAME_RE = /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

/** Targets handed to a network tool are validated tokens (IP, CIDR or
 *  hostname) — anything carrying shell metacharacters, whitespace or
 *  option-like leading dashes is rejected BEFORE plan construction
 *  (§82). Plans are argument arrays executed without a shell regardless;
 *  this is defense in depth, and it also stops option injection
 *  (a "target" of "-sV" must never become a flag). */
export function assertNetworkTargetToken(token: string): string {
  const t = token.trim();
  if (!t || t.length > 300 || /[\s;|&$`\\'"<>(){}[\]!*?~#]/.test(t) || t.startsWith("-")) {
    throw new AdapterConfigurationError(`invalid network target token: "${t.slice(0, 60)}"`);
  }
  if (isIpLiteral(t) || parseCidr(t)) return t;
  if (HOSTNAME_RE.test(t.replace(/\.$/, ""))) return t;
  throw new AdapterConfigurationError(`network target token is neither IP, CIDR nor hostname: "${t.slice(0, 60)}"`);
}

/** Targets for a run: the stage-input host list when present (in-scope
 *  inventory only — assembled by the worker store), else the scan target
 *  itself. Every token is validated. */
export function networkTargetsFor(target: AdapterTarget, config: Record<string, unknown>): string[] {
  const hosts = Array.isArray(config.hosts) ? (config.hosts as string[]) : [];
  const raw = hosts.length > 0 ? hosts : [target.value.includes("://") ? target.host : target.value];
  const out = [...new Set(raw.map((h) => assertNetworkTargetToken(String(h))))];
  if (out.length === 0) throw new AdapterConfigurationError("no network targets available for this stage");
  return out;
}

function portSpecFor(config: Record<string, unknown>): string {
  const custom = validateCustomPorts(config.customPorts);
  if (custom) return custom.join(",");
  const profile = portProfileById(typeof config.portProfile === "string" ? config.portProfile : DEFAULT_PORT_PROFILE_ID)
    ?? portProfileById(DEFAULT_PORT_PROFILE_ID)!;
  return portSpecForProfile(profile);
}

export const SCAN_MODE_FIELD: AdapterInputField = { name: "scanMode", type: "string", enumValues: ["HOST_DISCOVERY", "PORT_SCAN", "SERVICE", "SAFE_CHECKS"], description: "Pipeline stage mode — derived by the worker from the stage, never client input" };
export const PORT_PROFILE_FIELD: AdapterInputField = { name: "portProfile", type: "string", enumValues: ["WEB_COMMON", "COMMON_SERVICES", "STANDARD", "FULL_TCP", "UDP_SMALL"], description: "Governed port profile id (Prompt 10 §27) — derived by the worker from the assessment profile" };
export const CUSTOM_PORTS_FIELD: AdapterInputField = { name: "customPorts", type: "number[]", max: 1000, description: "Validated structured custom port set (§27) — never a raw CLI string" };
export const NETWORK_RATE_FIELD: AdapterInputField = { name: "rateLimit", type: "number", min: 1, max: 10000, description: "Requested packets/requests per second — clamped to the network budget and admin caps" };

// ---------------------------------------------------------------------------
// Nmap (§12–§16)
// ---------------------------------------------------------------------------

export class NmapAdapter extends NetworkAdapterBase {
  readonly executable = "nmap";
  readonly containerImage = "zerosweep/nmap"; // platform image built from the official release
  readonly versionArgs = ["--version"];
  protected readonly parser: NetworkParser = new NmapParser();
  readonly metadata = meta({
    id: "nmap", slug: "nmap", name: "Nmap",
    description: "Network discovery, port scanning, service/version fingerprinting, OS hinting and governed SAFE NSE checks. Commands are built ONLY from validated typed configuration (§13) — arbitrary Nmap arguments do not exist in this platform.",
    homepage: "https://nmap.org",
    category: "NETWORK", riskLevel: "MODERATE",
    capabilities: ["HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", "VERSION_DETECTION", "OS_HINTING", "SAFE_NETWORK_CHECKS"],
    supportedTargetTypes: ["IP_ADDRESS", "CIDR", "DOMAIN"],
    supportedOutputFormats: ["XML"],
    defaultTimeoutSeconds: 1200, maxTimeoutSeconds: 3600,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 1200 },
    requiredWorkerType: "NETWORK_EXTERNAL",
    inputSchema: [
      HOSTS_FIELD, TIMEOUT_FIELD, SCAN_MODE_FIELD, PORT_PROFILE_FIELD, CUSTOM_PORTS_FIELD, NETWORK_RATE_FIELD,
      { name: "hostDiscoveryMode", type: "string", enumValues: ["PING", "TCP_PROBES", "SKIP"], description: "Host discovery technique for the HOST_DISCOVERY mode" },
      { name: "serviceDetection", type: "boolean", description: "Enable service version detection (-sV) in SERVICE mode" },
      { name: "versionIntensity", type: "number", min: 0, max: 9, description: "Nmap version intensity 0–9" },
      { name: "osDetection", type: "boolean", description: "Enable OS hinting (-O, limited) in SERVICE mode — hints only, never fact (§35)" },
      { name: "approvedScriptIds", type: "string[]", description: "Administrator-approved REVIEW_REQUIRED NSE script ids (worker-derived from the profile, §14)" },
      { name: "udpScan", type: "boolean", description: "Add the small approved UDP profile in PORT_SCAN mode (§28)" },
      { name: "timingProfile", type: "string", enumValues: ["POLITE", "NORMAL", "AGGRESSIVE"], description: "Timing template — capped at T4; INSANE (T5) does not exist here" },
    ],
  });

  /** The governed script selection a run would use (§14) — recorded on
   *  the execution by the worker, mirroring the Nuclei snapshot pattern. */
  scriptSelectionFor(config: Record<string, unknown>): { snapshot: typeof NSE_POLICY_SNAPSHOT; selected: string[] } {
    const approved = Array.isArray(config.approvedScriptIds) ? (config.approvedScriptIds as string[]) : [];
    const { selected } = nmapScriptPolicy.selectScripts(approved);
    return { snapshot: NSE_POLICY_SNAPSHOT, selected: selected.map((s) => s.id) };
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const budget = clampNetworkBudget({});
    const targets = networkTargetsFor(target, config);
    if (targets.length > budget.maxHosts) {
      throw new AdapterConfigurationError(`nmap: ${targets.length} targets exceed the network budget maxHosts=${budget.maxHosts}`);
    }
    const mode = typeof config.scanMode === "string" ? config.scanMode : "PORT_SCAN";
    const rate = Math.min(typeof config.rateLimit === "number" ? config.rateLimit : budget.maxPacketsPerSecond, budget.maxPacketsPerSecond);
    const timing = config.timingProfile === "POLITE" ? "-T2" : config.timingProfile === "AGGRESSIVE" ? "-T4" : "-T3";
    const args: string[] = [timing, "--max-rate", String(rate)];

    if (mode === "HOST_DISCOVERY") {
      args.push("-sn");
      if (config.hostDiscoveryMode === "TCP_PROBES") args.push("-PS22,80,443", "-PA80,443");
      if (config.hostDiscoveryMode === "SKIP") throw new AdapterConfigurationError("nmap: host discovery mode SKIP is meaningless for a discovery run");
      args.push("-oX", "-", ...targets);
      return { args };
    }

    const ports = portSpecFor(config);
    if (mode === "PORT_SCAN") {
      args.push("-sT"); // connect scan: no raw-socket assumption in the worker container
      args.push("-p", ports);
      if (config.udpScan === true) {
        const udp = portProfileById("UDP_SMALL")!;
        const udpPorts = udp.ports.slice(0, budget.maxUdpPorts).join(",");
        args.push("-sU", "-p", `U:${udpPorts}`);
      }
      args.push("-oX", "-", ...targets);
      return { args };
    }

    // SERVICE and SAFE_CHECKS run against hosts already proven live:
    // -Pn skips redundant re-discovery of the pipeline's own inventory.
    args.push("-Pn", "-p", ports);
    if (config.serviceDetection !== false) {
      const intensity = typeof config.versionIntensity === "number" ? Math.max(0, Math.min(9, Math.floor(config.versionIntensity))) : 5;
      args.push("-sV", "--version-intensity", String(intensity));
    }
    if (mode === "SERVICE" && config.osDetection === true) args.push("-O", "--osscan-limit");
    if (mode === "SAFE_CHECKS") {
      const { selected } = this.scriptSelectionFor(config);
      if (selected.length === 0) throw new AdapterConfigurationError("nmap: governed NSE policy selected no scripts");
      // Scripts are named INDIVIDUALLY from the governed catalog — never
      // a category expression, never "default"/"vuln"/"brute" (§14).
      args.push("--script", selected.join(","));
    }
    args.push("-oX", "-", ...targets);
    return { args };
  }
}

// ---------------------------------------------------------------------------
// Naabu (§17)
// ---------------------------------------------------------------------------

export class NaabuAdapter extends NetworkAdapterBase {
  readonly executable = "naabu";
  readonly containerImage = "projectdiscovery/naabu";
  readonly versionArgs = ["-version"];
  protected readonly parser: NetworkParser = new NaabuParser();
  readonly metadata = meta({
    id: "naabu", slug: "naabu", name: "Naabu",
    description: "Fast port discovery feeding deeper Nmap fingerprinting (§17). Port lists come from governed profiles only.",
    homepage: "https://github.com/projectdiscovery/naabu",
    category: "RECON", riskLevel: "LOW",
    capabilities: ["PORT_DISCOVERY"],
    supportedTargetTypes: ["IP_ADDRESS", "CIDR", "DOMAIN"],
    supportedOutputFormats: ["JSONL"],
    defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1800,
    requiredWorkerType: "NETWORK_EXTERNAL",
    inputSchema: [HOSTS_FIELD, TIMEOUT_FIELD, PORT_PROFILE_FIELD, CUSTOM_PORTS_FIELD, NETWORK_RATE_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const budget = clampNetworkBudget({});
    const targets = networkTargetsFor(target, config);
    if (targets.length > budget.maxHosts) throw new AdapterConfigurationError(`naabu: target count exceeds budget maxHosts=${budget.maxHosts}`);
    const rate = Math.min(typeof config.rateLimit === "number" ? config.rateLimit : 1000, budget.maxPacketsPerSecond);
    return {
      args: ["-json", "-silent", "-p", portSpecFor(config), "-rate", String(rate)],
      stdin: targets.join("\n"),
    };
  }
}

// ---------------------------------------------------------------------------
// RustScan (§18)
// ---------------------------------------------------------------------------

export class RustScanAdapter extends NetworkAdapterBase {
  readonly executable = "rustscan";
  readonly containerImage = "rustscan/rustscan";
  readonly versionArgs = ["--version"];
  protected readonly parser: NetworkParser = new RustScanParser();
  readonly metadata = meta({
    id: "rustscan", slug: "rustscan", name: "RustScan",
    description: "Fast port discovery with controlled settings (§18). The downstream-command passthrough separator is NEVER emitted — RustScan output is parsed by ZeroSweep itself, nothing is handed to another program.",
    homepage: "https://github.com/RustScan/RustScan",
    category: "NETWORK", riskLevel: "LOW",
    capabilities: ["PORT_DISCOVERY"],
    supportedTargetTypes: ["IP_ADDRESS", "CIDR"],
    supportedOutputFormats: ["TEXT"],
    defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1800,
    requiredWorkerType: "NETWORK_EXTERNAL",
    inputSchema: [HOSTS_FIELD, TIMEOUT_FIELD, PORT_PROFILE_FIELD, CUSTOM_PORTS_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const budget = clampNetworkBudget({});
    const targets = networkTargetsFor(target, config);
    if (targets.length > budget.maxHosts) throw new AdapterConfigurationError(`rustscan: target count exceeds budget maxHosts=${budget.maxHosts}`);
    const profileId = typeof config.portProfile === "string" ? config.portProfile : DEFAULT_PORT_PROFILE_ID;
    const args = ["-a", targets.join(","), "-g", "--batch-size", "1000", "--timeout", "2000", "--tries", "1"];
    if (validateCustomPorts(config.customPorts)) args.push("--ports", validateCustomPorts(config.customPorts)!.join(","));
    else if (profileId === "FULL_TCP") args.push("--range", "1-65535");
    else args.push("--ports", portSpecFor(config));
    // Deliberately NO "--" separator and no -sV/-A style passthrough:
    // anything after "--" would be a command for another program (§18).
    return { args };
  }
}

// ---------------------------------------------------------------------------
// Masscan (§19/§20) — elevated-policy gated, never auto-selected
// ---------------------------------------------------------------------------

export class MasscanAdapter extends NetworkAdapterBase {
  readonly executable = "masscan";
  readonly containerImage = "zerosweep/masscan"; // platform image built from the official release
  readonly versionArgs = ["--version"];
  protected readonly parser: NetworkParser = new MasscanParser();
  protected readonly acceptableExitCodes = [0, 1] as const;
  readonly metadata = meta({
    id: "masscan", slug: "masscan", name: "Masscan",
    description: "High-speed port discovery (§19). ELEVATED risk: requires an explicit profile, administrator policy, strict clamped rate limits, an approved scope size and an appropriate worker. It is selected by NO default stage and the worker denies it without a recorded approval.",
    homepage: "https://github.com/robertdavidgraham/masscan",
    category: "NETWORK", riskLevel: "MODERATE",
    capabilities: ["HIGH_SPEED_PORT_DISCOVERY"],
    supportedTargetTypes: ["IP_ADDRESS", "CIDR"],
    supportedOutputFormats: ["JSON"],
    defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1800,
    requiresApproval: true,
    requiredWorkerType: "NETWORK_EXTERNAL",
    inputSchema: [
      HOSTS_FIELD, TIMEOUT_FIELD, PORT_PROFILE_FIELD, CUSTOM_PORTS_FIELD,
      { name: "maxRate", type: "number", min: 1, max: 100000, description: "Requested rate — ALWAYS clamped to the platform hard limits (§20)" },
    ],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const limits = clampMasscanLimits({ maxRate: typeof config.maxRate === "number" ? config.maxRate : undefined });
    const targets = networkTargetsFor(target, config);
    // Scope-size gate (§19/§20): total effective targets across explicit
    // hosts and CIDR ranges must fit the clamped maxTargets.
    let totalTargets = 0;
    for (const t of targets) {
      const cidr = parseCidr(t);
      totalTargets += cidr ? cidr.hostCount : 1;
    }
    if (totalTargets > limits.maxTargets) {
      throw new AdapterConfigurationError(`masscan: ${totalTargets} effective targets exceed the clamped limit of ${limits.maxTargets}`);
    }
    const ports = portSpecFor(config).split(",").filter(Boolean);
    if (ports.length > limits.maxPorts && !ports.some((p) => p.includes("-"))) {
      throw new AdapterConfigurationError(`masscan: ${ports.length} ports exceed the clamped limit of ${limits.maxPorts}`);
    }
    return {
      args: [
        "-p", portSpecFor(config),
        "--rate", String(limits.maxRate),
        "--wait", "0",
        "-oJ", "-",
        ...targets,
      ],
    };
  }
}

// ---------------------------------------------------------------------------
// Netdiscover (§21) + arp-scan (§22) — local layer-2, internal workers only
// ---------------------------------------------------------------------------

const LOCAL_DISCOVERY_SCHEMA: AdapterInputField[] = [
  HOSTS_FIELD, TIMEOUT_FIELD,
  { name: "networkRange", type: "string", description: "Approved local CIDR range (from the scan target/scope — never free text from a client)" },
  { name: "interfaceName", type: "string", max: 32, description: "Explicit local interface on the internal worker" },
];

function localRangeFor(target: AdapterTarget, config: Record<string, unknown>): string {
  const raw = typeof config.networkRange === "string" ? config.networkRange : target.value;
  const cidr = parseCidr(raw);
  if (!cidr) throw new AdapterConfigurationError(`local discovery requires a CIDR target/range, got "${String(raw).slice(0, 60)}"`);
  return cidr.canonical;
}

export class NetdiscoverAdapter extends NetworkAdapterBase {
  readonly executable = "netdiscover";
  readonly containerImage = "zerosweep/netdiscover";
  readonly versionArgs: string[] = [];
  protected readonly parser: NetworkParser = new NetdiscoverParser();
  readonly metadata = meta({
    id: "netdiscover", slug: "netdiscover", name: "Netdiscover",
    description: "ARP-based local network host discovery (§21). Meaningful ONLY from an explicitly approved local/internal worker with LOCAL_LAYER2_ACCESS — ordinary workers are denied by the executor gate (§65).",
    homepage: "https://github.com/netdiscover-scanner/netdiscover",
    category: "NETWORK", riskLevel: "LOW",
    capabilities: ["LOCAL_NETWORK_DISCOVERY"],
    supportedTargetTypes: ["CIDR"],
    supportedOutputFormats: ["TEXT"],
    defaultTimeoutSeconds: 300, maxTimeoutSeconds: 900,
    requiredWorkerType: "NETWORK_INTERNAL",
    inputSchema: [...LOCAL_DISCOVERY_SCHEMA],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const range = localRangeFor(target, config);
    const args = ["-r", range, "-N", "-P"];
    if (typeof config.interfaceName === "string" && /^[a-zA-Z0-9_.-]{1,32}$/.test(config.interfaceName)) args.push("-i", config.interfaceName);
    return { args };
  }
}

export class ArpScanAdapter extends NetworkAdapterBase {
  readonly executable = "arp-scan";
  readonly containerImage = "zerosweep/arp-scan";
  readonly versionArgs = ["--version"];
  protected readonly parser: NetworkParser = new ArpScanParser();
  readonly metadata = meta({
    id: "arp-scan", slug: "arp-scan", name: "arp-scan",
    description: "ARP-based local network discovery (§22). Requires an internal worker, an approved local network, explicit policy and the worker's layer-2 capability — broad host privileges are never granted to general workers (§24).",
    homepage: "https://github.com/royhills/arp-scan",
    category: "NETWORK", riskLevel: "LOW",
    capabilities: ["LOCAL_NETWORK_DISCOVERY"],
    supportedTargetTypes: ["CIDR"],
    supportedOutputFormats: ["XML", "TEXT"],
    defaultTimeoutSeconds: 300, maxTimeoutSeconds: 900,
    requiredWorkerType: "NETWORK_INTERNAL",
    inputSchema: [...LOCAL_DISCOVERY_SCHEMA],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const range = localRangeFor(target, config);
    const args = ["--xml", "-R", range];
    if (typeof config.interfaceName === "string" && /^[a-zA-Z0-9_.-]{1,32}$/.test(config.interfaceName)) args.push("-I", config.interfaceName);
    return { args };
  }
}

// ---------------------------------------------------------------------------
// tcpdump capture (§44) + tshark offline analysis (§45)
// ---------------------------------------------------------------------------

export class TcpdumpCaptureAdapter extends NetworkAdapterBase {
  readonly executable = "tcpdump";
  readonly containerImage = "zerosweep/tcpdump";
  readonly versionArgs = ["--version"];
  protected readonly parser: NetworkParser = {
    tool: "tcpdump",
    parse: () => ({
      assets: [], endpoints: [], technologies: [], services: [], findings: [], observations: [], exposures: [], transactions: [], captures: [],
      records: 0,
      warnings: ["tcpdump: capture bytes are stored as the execution artifact; analysis is performed offline by tshark (§45)"],
      metrics: {},
    }),
  };
  readonly metadata = meta({
    id: "tcpdump", slug: "tcpdump", name: "tcpdump",
    description: "Bounded packet capture for APPROVED CONTROLLED TEST ENVIRONMENTS only (§44): explicit interface, bounded duration, bounded file size. Never captures unrelated platform/user traffic. Raw captures are VIEW_RAW_PCAP-gated and audited (§47).",
    homepage: "https://www.tcpdump.org",
    category: "NETWORK", riskLevel: "PASSIVE",
    capabilities: ["PACKET_CAPTURE"],
    supportedTargetTypes: ["CIDR", "IP_ADDRESS"],
    supportedOutputFormats: ["TEXT"],
    defaultTimeoutSeconds: 300, maxTimeoutSeconds: 3600,
    requiredWorkerType: "PACKET_ANALYSIS",
    inputSchema: [
      TIMEOUT_FIELD,
      { name: "interfaceName", type: "string", required: true, max: 32, description: "Explicit capture interface on the packet-analysis worker — 'any' is refused" },
      { name: "durationSeconds", type: "number", min: 1, max: 3600, description: "Capture duration bound — clamped to the network budget (§56)" },
      { name: "maxPackets", type: "number", min: 1, max: 1000000, description: "Packet count bound for the capture" },
    ],
  });

  async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    const iface = config.interfaceName;
    if (typeof iface !== "string" || !/^[a-zA-Z0-9_.-]{1,32}$/.test(iface) || iface === "any") {
      throw new AdapterConfigurationError("tcpdump: an explicit interface name is required ('any' is refused, §44)");
    }
  }

  protected planFor(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const budget = clampNetworkBudget({});
    const duration = Math.min(
      typeof config.durationSeconds === "number" ? Math.floor(config.durationSeconds) : budget.maxPacketCaptureDurationSeconds,
      budget.maxPacketCaptureDurationSeconds,
    );
    const packets = typeof config.maxPackets === "number" ? Math.floor(config.maxPackets) : 100000;
    return {
      // -G rotates/stops at the duration bound, -W 1 keeps exactly one
      // file, -c caps packets, -s 0 full frames for offline analysis.
      // No -i any, no BPF expression field exists (§44/§82).
      args: ["-i", String(config.interfaceName), "-G", String(duration), "-W", "1", "-c", String(packets), "-s", "0", "-w", "capture.pcap"],
      outputFiles: ["capture.pcap"],
    };
  }

  async normalize(parsed: unknown): Promise<import("../findings/finding.types").NormalizedSecurityResult> {
    const base = await super.normalize(parsed);
    return {
      ...base,
      packetCaptures: [{
        artifactRef: "capture.pcap",
        format: "PCAP",
        source: "tcpdump",
      }],
    };
  }
}

export class TsharkAnalysisAdapter extends NetworkAdapterBase {
  readonly executable = "tshark";
  readonly containerImage = "zerosweep/tshark";
  readonly versionArgs = ["--version"];
  protected readonly parser: NetworkParser = new TsharkParser();
  readonly metadata = meta({
    id: "tshark", slug: "tshark", name: "tshark",
    description: "Offline analysis of authorized packet captures (§45): protocol hierarchy + HTTP transaction inventory from a stored capture artifact. Offline analysis is preferred over unrestricted live sniffing; the input is an artifact REFERENCE resolved inside the worker boundary, never a path or URL.",
    homepage: "https://www.wireshark.org",
    category: "NETWORK", riskLevel: "PASSIVE",
    capabilities: ["PACKET_ANALYSIS"],
    supportedTargetTypes: ["CIDR", "IP_ADDRESS"],
    supportedOutputFormats: ["JSON"],
    defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1800,
    requiredWorkerType: "PACKET_ANALYSIS",
    inputSchema: [
      TIMEOUT_FIELD,
      { name: "captureArtifactRef", type: "string", required: true, max: 512, description: "Object-storage reference of an authorized capture (scans/... key) — resolved by the worker, never a filesystem path" },
    ],
  });

  async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    const ref = config.captureArtifactRef;
    if (typeof ref !== "string" || !/^scans\/[A-Za-z0-9/_.#-]+(#[A-Za-z0-9/_.#-]+)?$/.test(ref) || ref.includes("..")) {
      throw new AdapterConfigurationError("tshark: captureArtifactRef must be a scans/ object-storage reference");
    }
  }

  protected planFor(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return {
      // The reference is resolved to a worker-local file by the trusted
      // execution layer; the plan carries the reference itself.
      args: ["-r", String(config.captureArtifactRef), "-T", "json", "-l"],
    };
  }
}
