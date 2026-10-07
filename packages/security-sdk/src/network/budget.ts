/**
 * Network scan budget + rate safety (Prompt 10 §20/§56–§58).
 *
 * Budgets are clamped in code: users may only ever LOWER a value, never
 * raise it past the administrator caps. Masscan has its own hard
 * platform limits (§20) — Masscan defaults are never relied on, and a
 * user-requested rate is always clamped to administrator policy.
 */
export interface NetworkBudget {
  maxHosts: number;
  maxPortsPerHost: number;
  maxTotalPorts: number;
  maxPacketsPerSecond: number;
  maxNetworkRequests: number;
  maxScanDurationSeconds: number;
  maxUdpPorts: number;
  maxPacketCaptureDurationSeconds: number;
  maxPacketCaptureSizeBytes: number;
  /** Parallelism ceilings (§58). */
  maxParallelHosts: number;
  maxParallelTools: number;
}

export const DEFAULT_NETWORK_BUDGET: NetworkBudget = {
  maxHosts: 256,
  maxPortsPerHost: 1000,
  maxTotalPorts: 65536,
  maxPacketsPerSecond: 1000,
  maxNetworkRequests: 100000,
  maxScanDurationSeconds: 3600,
  maxUdpPorts: 25,
  maxPacketCaptureDurationSeconds: 300,
  maxPacketCaptureSizeBytes: 100 * 1024 * 1024,
  maxParallelHosts: 16,
  maxParallelTools: 2,
};

export const ADMIN_NETWORK_CAPS: NetworkBudget = {
  maxHosts: 65536,
  maxPortsPerHost: 65535,
  maxTotalPorts: 1048576,
  maxPacketsPerSecond: 10000,
  maxNetworkRequests: 1000000,
  maxScanDurationSeconds: 21600,
  maxUdpPorts: 1000,
  maxPacketCaptureDurationSeconds: 3600,
  maxPacketCaptureSizeBytes: 1024 * 1024 * 1024,
  maxParallelHosts: 64,
  maxParallelTools: 4,
};

const KEYS = Object.keys(DEFAULT_NETWORK_BUDGET) as (keyof NetworkBudget)[];

export function clampNetworkBudget(requested: Partial<NetworkBudget> = {}): NetworkBudget {
  const out = { ...DEFAULT_NETWORK_BUDGET };
  for (const key of KEYS) {
    const v = requested[key];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) {
      out[key] = Math.min(Math.floor(v), ADMIN_NETWORK_CAPS[key]);
    }
  }
  // Cross-field consistency: total ports can never exceed hosts × per-host.
  out.maxTotalPorts = Math.min(out.maxTotalPorts, out.maxHosts * out.maxPortsPerHost);
  return out;
}

/** Masscan hard platform limits (§20). The adapter clamps EVERY run to
 *  these; nothing a user or profile requests can exceed them. */
export interface MasscanLimits {
  maxRate: number;
  maxTargets: number;
  maxPorts: number;
  maxDurationSeconds: number;
}

export const MASSCAN_HARD_LIMITS: MasscanLimits = {
  maxRate: 10000,
  maxTargets: 4096,
  maxPorts: 100,
  maxDurationSeconds: 1800,
};

export const MASSCAN_DEFAULTS: MasscanLimits = {
  maxRate: 1000,
  maxTargets: 256,
  maxPorts: 25,
  maxDurationSeconds: 600,
};

export function clampMasscanLimits(requested: Partial<MasscanLimits> = {}): MasscanLimits {
  const clamp = (v: number | undefined, fallback: number, cap: number) =>
    typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.min(Math.floor(v), cap) : fallback;
  return {
    maxRate: clamp(requested.maxRate, MASSCAN_DEFAULTS.maxRate, MASSCAN_HARD_LIMITS.maxRate),
    maxTargets: clamp(requested.maxTargets, MASSCAN_DEFAULTS.maxTargets, MASSCAN_HARD_LIMITS.maxTargets),
    maxPorts: clamp(requested.maxPorts, MASSCAN_DEFAULTS.maxPorts, MASSCAN_HARD_LIMITS.maxPorts),
    maxDurationSeconds: clamp(requested.maxDurationSeconds, MASSCAN_DEFAULTS.maxDurationSeconds, MASSCAN_HARD_LIMITS.maxDurationSeconds),
  };
}
