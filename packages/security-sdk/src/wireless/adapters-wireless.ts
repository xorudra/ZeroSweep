/**
 * Prompt 19 — wireless adapters (§16/§19/§23/§24).
 *
 *  - KismetAdapter: PASSIVE discovery on a registered, approved
 *    sensor (§12/§16). The plan names the worker-derived sensor
 *    interface and a bounded passive session; Kismet listens — the
 *    plan contains no transmit, association or probe options, and no
 *    such options are expressible in config (§78).
 *  - TsharkWirelessAdapter: offline 802.11 analysis of an APPROVED
 *    capture artifact (§24). The field set is the FIXED platform
 *    constant TSHARK_WIRELESS_FIELDS; display filters are not
 *    expressible (§78).
 *  - HcxToolsAdapter: hcxpcapngtool in METADATA-SUMMARY mode over an
 *    approved capture (§23). Hash-export flags (-o/-E/--pmkid) do not
 *    exist in the plan vocabulary; authentication material in a
 *    capture is counted, never extracted (§67).
 *  - AircrackMetadataAdapter: aircrack-ng OFFLINE capture inspection
 *    (§19/§20). The plan is the capture reference alone — no key,
 *    wordlist, or deauthentication argument is expressible, and
 *    AircrackPolicy refuses such config keys at validation.
 *
 * Wifite and hcxdumptool have NO adapters (§21/§22/§64): they exist
 * as DISABLED registrations only.
 */
import type { ToolMetadata } from "../adapter/adapter.types";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ReconPlanParts } from "../recon/recon-adapter.base";
import {
  parseAircrackCaptureInfo, parseHcxPcapngToolSummary, parseKismetDevices, parseTsharkWirelessFields,
  TSHARK_WIRELESS_FIELDS, type WirelessParserContext,
} from "./parsers-wireless";
import { WirelessAdapterBase, wlConfigStr } from "./wireless-adapter.base";
import type { ParsedWireless } from "./types";

function wirelessMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "licenseType" | "capabilities">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "WIRELESS",
    executionMode: "CONTAINER",
    riskLevel: "PASSIVE",
    requiresApproval: false,
    supportedTargetTypes: ["WIRELESS_LAB"],
    supportedOutputFormats: ["JSON"],
    requiresCredentials: [],
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 900, maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "1Gi", timeoutSeconds: 900 },
    requiredWorkerType: "WIRELESS_PASSIVE_ANALYSIS",
    ...partial,
  };
}

const SENSOR_INPUTS = [
  { name: "wirelessSensorRef", type: "string", description: "Registered WirelessSensor reference — worker-derived" },
  { name: "wirelessSensorInterface", type: "string", description: "Approved sensor interface name — worker-derived from the sensor record (§12)" },
  { name: "wirelessEnvironmentId", type: "string", description: "Registered WirelessEnvironment id — worker-derived" },
  { name: "workspaceKey", type: "string", description: "Workspace pseudonymization key — worker-derived (§9)" },
  { name: "timeoutSeconds", type: "number", description: "Execution timeout override" },
] as const;

const CAPTURE_INPUTS = [
  { name: "wirelessCaptureRef", type: "string", description: "Approved WirelessCapture artifact reference — worker-derived" },
  { name: "wirelessCaptureId", type: "string", description: "Registered WirelessCapture id — worker-derived" },
  { name: "wirelessSensorRef", type: "string", description: "Sensor that produced the capture — worker-derived" },
  { name: "wirelessEnvironmentId", type: "string", description: "Registered WirelessEnvironment id — worker-derived" },
  { name: "workspaceKey", type: "string", description: "Workspace pseudonymization key — worker-derived (§9)" },
  { name: "timeoutSeconds", type: "number", description: "Execution timeout override" },
] as const;

// ── Kismet (§16) ────────────────────────────────────────────────────

export class KismetAdapter extends WirelessAdapterBase {
  readonly executable = "kismet";
  readonly containerImage = "dsrclone/kismet:local";
  readonly versionArgs = ["--version"];
  readonly metadata: ToolMetadata = wirelessMeta({
    id: "adapter-kismet", slug: "kismet", name: "Kismet",
    description: "Kismet passive wireless discovery (Prompt 19 §16): access-point inventory, station observation, channel observation and wireless security metadata from a registered approved sensor. Passive collection profiles only — Kismet listens; it never transmits, associates or probes.",
    capabilities: ["PASSIVE_WIFI_DISCOVERY", "ACCESS_POINT_INVENTORY", "STATION_OBSERVATION", "CHANNEL_OBSERVATION", "WIRELESS_SECURITY_METADATA"],
    licenseType: "OPEN_SOURCE", requiresApproval: true,
    defaultTimeoutSeconds: 1200, maxTimeoutSeconds: 3600,
    resources: { cpu: "1", memory: "1Gi", timeoutSeconds: 1200 },
    inputSchema: [...SENSOR_INPUTS],
  });

  protected parseWireless(text: string, ctx: WirelessParserContext): ParsedWireless {
    return parseKismetDevices(text, ctx);
  }

  protected wirelessPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const iface = wlConfigStr(config, "wirelessSensorInterface");
    if (!iface) throw new AdapterConfigurationError("kismet plan requires an approved sensor interface (worker-derived from the registered sensor, §12)");
    // Passive capture source only: no transmit/association options
    // exist in this vocabulary (§16).
    return { args: ["-c", `${iface}:type=linuxwifi`, "--no-ncurses", "--silent"] };
  }
}

// ── tshark wireless (§24) ───────────────────────────────────────────

export class TsharkWirelessAdapter extends WirelessAdapterBase {
  readonly executable = "tshark";
  readonly containerImage = "dsrclone/tshark:local";
  readonly versionArgs = ["--version"];
  readonly metadata: ToolMetadata = wirelessMeta({
    id: "adapter-tshark-wireless", slug: "tshark-wireless", name: "tshark (wireless)",
    description: "tshark offline 802.11 frame analysis (Prompt 19 §24): AP inventory, security metadata and passive deauthentication/disassociation burst detection over an APPROVED capture artifact, using the fixed platform field set. Arbitrary display filters are not expressible (§78).",
    capabilities: ["PCAP_ANALYSIS", "FRAME_ANALYSIS_80211", "WIRELESS_PROTOCOL_METADATA"],
    licenseType: "OPEN_SOURCE",
    defaultTimeoutSeconds: 900, maxTimeoutSeconds: 1800,
    inputSchema: [...CAPTURE_INPUTS],
  });

  protected parseWireless(text: string, ctx: WirelessParserContext): ParsedWireless {
    return parseTsharkWirelessFields(text, ctx);
  }

  protected wirelessPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const ref = wlConfigStr(config, "wirelessCaptureRef") ?? wlConfigStr(config, "wirelessCaptureId");
    if (!ref) throw new AdapterConfigurationError("tshark-wireless plan requires an approved capture artifact reference (worker-derived, §26)");
    const args = ["-r", ref, "-T", "fields"];
    for (const field of TSHARK_WIRELESS_FIELDS) args.push("-e", field);
    return { args };
  }
}

// ── hcxtools (§23) ──────────────────────────────────────────────────

export class HcxToolsAdapter extends WirelessAdapterBase {
  readonly executable = "hcxpcapngtool";
  readonly containerImage = "dsrclone/hcxtools:local";
  readonly versionArgs = ["--version"];
  readonly metadata: ToolMetadata = wirelessMeta({
    id: "adapter-hcxtools", slug: "hcxtools", name: "hcxtools",
    description: "hcxtools offline capture processing (Prompt 19 §23): hcxpcapngtool session-summary metadata over APPROVED capture artifacts only. Hash-export modes are not expressible; authentication material is counted, never extracted (§67).",
    capabilities: ["OFFLINE_CAPTURE_PROCESSING", "CAPTURE_METADATA_EXTRACTION"],
    licenseType: "OPEN_SOURCE", riskLevel: "LOW", requiresApproval: true,
    defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1200,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 600 },
    inputSchema: [...CAPTURE_INPUTS],
  });

  protected parseWireless(text: string, ctx: WirelessParserContext): ParsedWireless {
    return parseHcxPcapngToolSummary(text, ctx);
  }

  protected wirelessPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const ref = wlConfigStr(config, "wirelessCaptureRef") ?? wlConfigStr(config, "wirelessCaptureId");
    if (!ref) throw new AdapterConfigurationError("hcxtools plan requires an approved capture artifact reference (worker-derived, §26)");
    // Summary mode ONLY: the capture path is the sole argument. The
    // hash-export flags (-o, -E, --pmkid, --hccapx) are absent from
    // the plan vocabulary by construction (§23/§67).
    return { args: [ref] };
  }
}

// ── Aircrack-ng metadata (§19/§20) ──────────────────────────────────

export class AircrackMetadataAdapter extends WirelessAdapterBase {
  readonly executable = "aircrack-ng";
  readonly containerImage = "dsrclone/aircrack-ng:local";
  readonly versionArgs = ["--version"];
  readonly metadata: ToolMetadata = wirelessMeta({
    id: "adapter-aircrack-ng", slug: "aircrack-ng", name: "Aircrack-ng (metadata)",
    description: "Aircrack-ng restricted to approved non-cracking capabilities (Prompt 19 §19/§20): offline capture inspection, capture metadata analysis and wireless configuration analysis. Credential cracking, key recovery and deauthentication workflows are DISABLED by AircrackPolicy and are not expressible in any plan.",
    capabilities: ["CAPTURE_METADATA_ANALYSIS", "WIRELESS_CONFIGURATION_ANALYSIS", "OFFLINE_CAPTURE_INSPECTION"],
    licenseType: "OPEN_SOURCE", riskLevel: "MODERATE", requiresApproval: true,
    defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1200,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 600 },
    inputSchema: [...CAPTURE_INPUTS],
  });

  protected parseWireless(text: string, ctx: WirelessParserContext): ParsedWireless {
    return parseAircrackCaptureInfo(text, ctx);
  }

  protected wirelessPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const ref = wlConfigStr(config, "wirelessCaptureRef") ?? wlConfigStr(config, "wirelessCaptureId");
    if (!ref) throw new AdapterConfigurationError("aircrack-ng plan requires an approved capture artifact reference (worker-derived, §26)");
    // Capture-inspection mode ONLY: the capture reference is the sole
    // argument. No -w/-b/-l key or target arguments exist here (§20).
    return { args: [ref] };
  }
}
