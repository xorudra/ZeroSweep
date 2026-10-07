/**
 * Prompt 18 — binary adapter registry (§10/§95).
 *
 * createBinaryAdapters returns the THREE executing static adapters
 * (checksec, the reused+extended Ghidra, radare2). The commercial
 * connectors (IDA / Binary Ninja), the ANALYST_TOOL (Cutter) and the
 * lab debuggers (GDB / pwndbg) are NOT adapters: they surface in
 * health as connector/descriptor entries with honest states
 * (binaryHealthBySlug) — never as executable pipeline tools.
 */
import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import { ProcessToolRunner, type ToolRunner } from "../recon/runner";
import { ChecksecAdapter, GhidraBinaryAdapter, Radare2Adapter } from "./adapters-binary";
import { BinaryNinjaConnector, IdaConnector } from "./connectors";
import { BINARY_DISABLED_REGISTRATIONS, INERT_BINARY_DEPS, type BinaryConnectorDeps } from "./types";

export const BINARY_SLUGS = ["checksec", "radare2", "ghidra"] as const;
/** Tool stages the binary static adapters may run in (§10/§11). */
export const BINARY_STATIC_STAGES = ["BINARY_HARDENING_ANALYSIS", "BINARY_STATIC_ANALYSIS"] as const;

export function createBinaryAdapters(runner: ToolRunner = new ProcessToolRunner()): SecurityToolAdapter[] {
  return [new ChecksecAdapter(runner), new Radare2Adapter(runner), new GhidraBinaryAdapter(runner)];
}

export function registerBinaryAdapters(registry: ToolRegistry, runner: ToolRunner = new ProcessToolRunner()): string[] {
  const registered: string[] = [];
  for (const adapter of createBinaryAdapters(runner)) {
    if (registry.resolve(adapter.metadata.slug)) continue;
    registry.register(adapter);
    registered.push(adapter.metadata.slug);
  }
  return registered;
}

/** §95 plan-time health record (synchronous, mirrors the mobile
 *  family's record): executing adapters report their PATH probe;
 *  commercial connectors report NOT_CONFIGURED at plan time (their
 *  license state resolves in the worker, §96); governed descriptors
 *  report their non-executing state verbatim. */
export function binaryHealthRecord(
  adapters: SecurityToolAdapter[],
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const adapter of adapters) {
    if ((BINARY_SLUGS as readonly string[]).includes(adapter.metadata.slug)) {
      const probe = (adapter as { isExecutablePresent?: () => boolean }).isExecutablePresent?.();
      out[adapter.metadata.slug] = probe ? "HEALTHY" : "UNAVAILABLE";
    }
  }
  out["ida"] = "NOT_CONFIGURED";
  out["binary-ninja"] = "NOT_CONFIGURED";
  for (const reg of BINARY_DISABLED_REGISTRATIONS) {
    out[reg.slug] = reg.executionState;
  }
  return out;
}

/** §95 health surface: executing adapters probe their binary;
 *  connectors report license state; descriptors report their
 *  governed non-executing state. Nothing here fabricates readiness. */
export async function binaryHealthBySlug(
  adapters: SecurityToolAdapter[],
  deps: BinaryConnectorDeps = INERT_BINARY_DEPS,
): Promise<Record<string, { status: string; detail?: string }>> {
  const out: Record<string, { status: string; detail?: string }> = {};
  for (const adapter of adapters) {
    if ((BINARY_SLUGS as readonly string[]).includes(adapter.metadata.slug)) {
      out[adapter.metadata.slug] = await adapter.healthCheck();
    }
  }
  const ida = new IdaConnector(deps);
  const bn = new BinaryNinjaConnector(deps);
  out["ida"] = await ida.healthCheck();
  out["binary-ninja"] = await bn.healthCheck();
  for (const reg of BINARY_DISABLED_REGISTRATIONS) {
    out[reg.slug] = { status: reg.executionState, detail: reg.reason };
  }
  return out;
}
