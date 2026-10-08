/**
 * Network VAPT V2 tool capabilities + health view (Prompt 33 §120,
 * §136/§137).
 *
 * Every V2 tool runs in an isolated scanner worker via argument arrays
 * (§137) — never a shell string. In THIS deployment no live worker
 * transport is wired for network tools, so execution mode is
 * FIXTURE_ONLY and health is honestly NOT_CONFIGURED unless a registry
 * record proves otherwise. Masscan's capability is gated (§27) and
 * Metasploit has NO execution capability at all (§75).
 */

export interface NetworkToolCapability {
  slug: string;
  name: string;
  executionMode: "FIXTURE_ONLY" | "WORKER" | "NOT_PROVISIONED";
  requiresWorkerCapability?: string;
  notes: string;
}

export const NETWORK_TOOL_CAPABILITIES: Record<string, NetworkToolCapability> = {
  nmap: { slug: "nmap", name: "Nmap", executionMode: "FIXTURE_ONLY", notes: "Governed service detection + SAFE/DISCOVERY/VERSION scripts; VULN_APPROVED set under §37 gates" },
  naabu: { slug: "naabu", name: "Naabu", executionMode: "FIXTURE_ONLY", notes: "Bounded port discovery (rate/ports/hosts/timeouts, §29)" },
  rustscan: { slug: "rustscan", name: "RustScan", executionMode: "FIXTURE_ONLY", notes: "Controlled fast discovery; candidates confirmed by Nmap service detection (§28)" },
  masscan: { slug: "masscan", name: "Masscan", executionMode: "FIXTURE_ONLY", requiresWorkerCapability: "HIGH_THROUGHPUT", notes: "Gated (§27): explicit profile + permission + platform record + hard limits; never a default" },
  netdiscover: { slug: "netdiscover", name: "Netdiscover", executionMode: "FIXTURE_ONLY", requiresWorkerCapability: "L2_LOCAL_NETWORK", notes: "L2 discovery only where the worker is legitimately attached to the authorized local network (§20)" },
  "arp-scan": { slug: "arp-scan", name: "arp-scan", executionMode: "FIXTURE_ONLY", requiresWorkerCapability: "L2_LOCAL_NETWORK", notes: "L2 discovery only where the worker is legitimately attached to the authorized local network (§20)" },
  "greenbone-openvas": { slug: "greenbone-openvas", name: "Greenbone/OpenVAS", executionMode: "FIXTURE_ONLY", notes: "Connector (Prompt 11) under logical profiles; unconfigured instances report NOT_CONFIGURED" },
  "nessus-professional": { slug: "nessus-professional", name: "Nessus Professional", executionMode: "FIXTURE_ONLY", notes: "Commercial connector (Prompt 11); credentials are secret references, never logged (§59)" },
  testssl: { slug: "testssl", name: "testssl.sh", executionMode: "FIXTURE_ONLY", notes: "TLS analysis (§53)" },
  sslyze: { slug: "sslyze", name: "SSLyze", executionMode: "FIXTURE_ONLY", notes: "TLS analysis (§53)" },
  tshark: { slug: "tshark", name: "tshark", executionMode: "FIXTURE_ONLY", notes: "Structured protocol metadata from captures (§91) — passive only" },
  tcpdump: { slug: "tcpdump", name: "tcpdump", executionMode: "FIXTURE_ONLY", requiresWorkerCapability: "PACKET_CAPTURE", notes: "Bounded passive capture on authorized interfaces (§84/§85)" },
  metasploit: { slug: "metasploit", name: "Metasploit (verification policy)", executionMode: "NOT_PROVISIONED", notes: "Policy layer only (§75–§82): requests are evaluated + recorded, never executed automatically" },
};

export function networkToolCapability(slug: string): NetworkToolCapability {
  return NETWORK_TOOL_CAPABILITIES[slug] ?? { slug, name: slug, executionMode: "FIXTURE_ONLY", notes: "No V2 capability record — treated as fixture-only" };
}

export function networkToolHealthView(
  entry: { slug: string; enabled: boolean; healthStatus: string } | undefined,
  capability: NetworkToolCapability,
): { slug: string; name: string; status: string; executionMode: string; notes: string } {
  if (capability.executionMode === "NOT_PROVISIONED") {
    return { slug: capability.slug, name: capability.name, status: "NOT_PROVISIONED", executionMode: capability.executionMode, notes: capability.notes };
  }
  if (!entry) return { slug: capability.slug, name: capability.name, status: "NOT_CONFIGURED", executionMode: capability.executionMode, notes: capability.notes };
  if (!entry.enabled) return { slug: capability.slug, name: capability.name, status: "DISABLED", executionMode: capability.executionMode, notes: capability.notes };
  return { slug: capability.slug, name: capability.name, status: entry.healthStatus, executionMode: capability.executionMode, notes: capability.notes };
}

/** §137: build an argument ARRAY for a worker invocation. Targets and
 *  ports arrive pre-validated (normalization + scope lock); user text
 *  is never concatenated into a command line — there is no shell. */
export function buildWorkerArgv(tool: string, args: string[]): string[] {
  for (const arg of args) {
    if (/[\n\r\0]/.test(arg)) throw new Error("Worker argument contains control characters — refused (§137)");
  }
  return [tool, ...args];
}
