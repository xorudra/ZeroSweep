import { MASSCAN_HARD_LIMITS, clampMasscanLimits } from "../network/budget";
import type { NetworkScanBudget } from "./types";

/**
 * Network VAPT V2 budgets, the platform hard ceiling and the Masscan
 * gate (Prompt 33 §17/§18/§27, §139).
 *
 * Budgets clamp ONE-DIRECTIONALLY against a platform ceiling that no
 * workspace admin can raise (§18) — the same discipline as Prompt 10's
 * NetworkBudget and Prompt 32's request ceiling, expressed in network
 * units (hosts / ports / rate / concurrency / duration). The clamped
 * fields are returned so a plan can show exactly what was refused.
 *
 * Masscan is governed separately and more strictly (§27): it needs an
 * explicit high-throughput profile flag, the RUN_HIGH_THROUGHPUT_PORT_SCAN
 * permission, a recorded platform permission, strict scope and the
 * Prompt 10 hard limits. Absent any one of those the verdict is
 * MASSCAN_NOT_APPROVED — the gate from Prompt 10 stays structural.
 */

export const NETWORK_PLATFORM_CEILING: NetworkScanBudget = {
  maxHosts: 4_096,
  maxPortsPerHost: 1_000,
  maxTotalPorts: 262_144,
  maxRatePerSecond: 10_000,
  maxConcurrency: 16,
  maxDurationSeconds: 21_600,
  maxUdpPorts: 1_000,
};

export interface NetworkBudgetClampResult {
  budget: NetworkScanBudget;
  clampedFields: string[];
}

function clampField(name: keyof NetworkScanBudget, value: number | undefined, ceiling: number, fallback: number, clamped: string[]): number {
  const v = typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
  if (v > ceiling) { clamped.push(name); return ceiling; }
  return v;
}

export function clampNetworkVaptBudget(requested: Partial<NetworkScanBudget>, defaults: NetworkScanBudget): NetworkBudgetClampResult {
  const clamped: string[] = [];
  const budget: NetworkScanBudget = {
    maxHosts: clampField("maxHosts", requested.maxHosts, NETWORK_PLATFORM_CEILING.maxHosts, defaults.maxHosts, clamped),
    maxPortsPerHost: clampField("maxPortsPerHost", requested.maxPortsPerHost, NETWORK_PLATFORM_CEILING.maxPortsPerHost, defaults.maxPortsPerHost, clamped),
    maxTotalPorts: clampField("maxTotalPorts", requested.maxTotalPorts, NETWORK_PLATFORM_CEILING.maxTotalPorts, defaults.maxTotalPorts, clamped),
    maxRatePerSecond: clampField("maxRatePerSecond", requested.maxRatePerSecond, NETWORK_PLATFORM_CEILING.maxRatePerSecond, defaults.maxRatePerSecond, clamped),
    maxConcurrency: clampField("maxConcurrency", requested.maxConcurrency, NETWORK_PLATFORM_CEILING.maxConcurrency, defaults.maxConcurrency, clamped),
    maxDurationSeconds: clampField("maxDurationSeconds", requested.maxDurationSeconds, NETWORK_PLATFORM_CEILING.maxDurationSeconds, defaults.maxDurationSeconds, clamped),
    maxUdpPorts: clampField("maxUdpPorts", requested.maxUdpPorts, NETWORK_PLATFORM_CEILING.maxUdpPorts, defaults.maxUdpPorts, clamped),
  };
  // Cross-field consistency (§17): totals never exceed hosts × per-host.
  budget.maxTotalPorts = Math.min(budget.maxTotalPorts, budget.maxHosts * budget.maxPortsPerHost);
  return { budget, clampedFields: clamped };
}

/** §10: estimated workload class from the clamped budget + host count. */
export function workloadClassOf(budget: NetworkScanBudget, hostCount: number): "SMALL" | "MEDIUM" | "LARGE" {
  const work = hostCount * Math.min(budget.maxPortsPerHost, 1_000);
  if (work <= 2_500) return "SMALL";
  if (work <= 65_536) return "MEDIUM";
  return "LARGE";
}

export interface MasscanGateInput {
  /** The caller explicitly asked for high-throughput discovery (§27). */
  explicitlyRequested: boolean;
  /** Caller holds RUN_HIGH_THROUGHPUT_PORT_SCAN (§129). */
  highThroughputPermission: boolean;
  /** A platform-level permission record exists (admin policy, §27). */
  platformPermission: boolean;
  /** Effective in-scope host count after scope lock. */
  scopeHostCount: number;
  /** Effective port count from the plan's port policy. */
  scopePortCount: number;
  requestedRate?: number;
}

export interface MasscanGateResult {
  approved: boolean;
  /** MASSCAN_NOT_APPROVED whenever the gate fails — never silent (§27). */
  verdict: "APPROVED" | "MASSCAN_NOT_APPROVED";
  reasons: string[];
  /** The Prompt 10 hard-clamped limits when approved. */
  limits?: ReturnType<typeof clampMasscanLimits>;
}

/**
 * The Masscan gate (§27/§139). Every condition is mandatory; the rate
 * is clamped to the Prompt 10 hard limits and an excessive request is
 * visible in the reasons, never silently honored.
 */
export function evaluateMasscanGate(input: MasscanGateInput): MasscanGateResult {
  const reasons: string[] = [];
  if (!input.explicitlyRequested) reasons.push("Masscan is never a default: it requires an explicit high-throughput request (§27)");
  if (!input.highThroughputPermission) reasons.push("Caller lacks RUN_HIGH_THROUGHPUT_PORT_SCAN (§129)");
  if (!input.platformPermission) reasons.push("No platform permission record for high-throughput scanning (§27)");
  if (input.scopeHostCount > MASSCAN_HARD_LIMITS.maxTargets) reasons.push(`Scope spans ${input.scopeHostCount} hosts — above the Masscan hard cap of ${MASSCAN_HARD_LIMITS.maxTargets} (§27)`);
  if (input.scopePortCount > MASSCAN_HARD_LIMITS.maxPorts) reasons.push(`Port policy spans ${input.scopePortCount} ports — above the Masscan hard cap of ${MASSCAN_HARD_LIMITS.maxPorts} (§27)`);
  if (typeof input.requestedRate === "number" && input.requestedRate > MASSCAN_HARD_LIMITS.maxRate) {
    reasons.push(`Requested rate ${input.requestedRate}/s exceeds the platform hard limit of ${MASSCAN_HARD_LIMITS.maxRate}/s — clamped, and the request is refused rather than silently honored (§139)`);
  }
  if (reasons.length > 0) return { approved: false, verdict: "MASSCAN_NOT_APPROVED", reasons };
  return {
    approved: true, verdict: "APPROVED", reasons: [],
    limits: clampMasscanLimits({ maxRate: input.requestedRate }),
  };
}
