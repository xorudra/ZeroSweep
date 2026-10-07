/**
 * Worker observability counters (Prompt 4 §62). Deliberately label-free:
 * metrics never carry target values, credentials or per-tenant identifiers.
 */
export class MetricsRegistry {
  private readonly counters = new Map<string, number>();
  private readonly gauges = new Map<string, number>();

  inc(name: string, by = 1): void {
    this.counters.set(name, (this.counters.get(name) ?? 0) + by);
  }
  setGauge(name: string, value: number): void {
    this.gauges.set(name, value);
  }
  snapshot(): { counters: Record<string, number>; gauges: Record<string, number> } {
    return { counters: Object.fromEntries(this.counters), gauges: Object.fromEntries(this.gauges) };
  }
}

export const METRICS = {
  scansQueued: "scans_queued",
  scansRunning: "scans_running",
  scanDurationMs: "scan_duration_ms",
  stageDurationMs: "stage_duration_ms",
  toolExecutionDurationMs: "tool_execution_duration_ms",
  queueDepth: "queue_depth",
  workerCount: "worker_count",
  workerHeartbeatAgeMs: "worker_heartbeat_age_ms",
  failures: "failures",
  timeouts: "timeouts",
  cancellations: "cancellations",
} as const;

export const metrics = new MetricsRegistry();
