/**
 * Prompt 17 — mobile adapter registry + health (§10/§16/§102).
 *
 * Six adapters are implemented: the MobSF connector (admin-registered
 * instance only), JADX, apktool, Ghidra (headless static), and the
 * two lab adapters (ADB, mitmproxy) that are inert without a wired
 * lab transport + approved session. Frida/Objection are governed
 * DISABLED / APPROVAL_REQUIRED registrations with NO adapter
 * (§69–§74): they can never be selected by a stage.
 * Health discipline mirrors the other families: CLI adapters probe
 * their binary; connectors report NOT_CONFIGURED until configured.
 */
import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import { ProcessToolRunner, type ToolRunner } from "../recon/runner";
import { AdbLabAdapter, GhidraAdapter, JadxAdapter, ApktoolAdapter, MitmproxyAdapter, MobSFConnectorAdapter, MOBILE_SLUGS } from "./adapters-mobile";
import { INERT_MOBILE_DEPS, MOBILE_DISABLED_REGISTRATIONS, type MobileConnectorDeps } from "./types";

export { MOBILE_SLUGS };
export const MOBILE_DISABLED_SLUGS: string[] = MOBILE_DISABLED_REGISTRATIONS.map((r) => r.slug);
const CONNECTOR_SLUGS = ["mobsf", "adb", "mitmproxy"] as const;

export function createMobileAdapters(runner?: ToolRunner, deps: MobileConnectorDeps = INERT_MOBILE_DEPS): SecurityToolAdapter[] {
  const r = runner ?? new ProcessToolRunner();
  return [
    new MobSFConnectorAdapter(deps),
    new JadxAdapter(r),
    new ApktoolAdapter(r),
    new GhidraAdapter(r),
    new AdbLabAdapter(deps),
    new MitmproxyAdapter(deps),
  ];
}

export function registerMobileAdapters(registry: ToolRegistry, runner?: ToolRunner, deps: MobileConnectorDeps = INERT_MOBILE_DEPS): SecurityToolAdapter[] {
  const adapters = createMobileAdapters(runner, deps);
  for (const adapter of adapters) {
    // mitmproxy is already registered by the API-security family
    // (Prompt 9): one adapter serves both the API traffic stages and
    // the mobile traffic stage (allowlisted by slug) — never a
    // duplicate registration.
    if (registry.resolve(adapter.metadata.slug)) continue;
    registry.register(adapter);
  }
  return adapters;
}

export interface MobileHealthEntry {
  slug: string;
  status: string; // HEALTHY | UNAVAILABLE | NOT_CONFIGURED | DISABLED | APPROVAL_REQUIRED
  detail?: string;
}

/** Synchronous plan-time health record (§102): CLI adapters use the
 *  synchronous PATH probe; connectors are NOT_CONFIGURED constants at
 *  plan time (per-instance/lab state resolves in the worker, §14/§16);
 *  Frida/Objection report their governed states. */
export function mobileHealthBySlug(
  adapters: SecurityToolAdapter[],
  deps: MobileConnectorDeps = INERT_MOBILE_DEPS,
): Record<string, string> {
  const out: Record<string, string> = {};
  const anyTransport = Object.keys(deps.transports).length > 0;
  for (const adapter of adapters) {
    const slug = adapter.metadata.slug;
    if ((CONNECTOR_SLUGS as readonly string[]).includes(slug)) {
      out[slug] = anyTransport ? "UNKNOWN" : "NOT_CONFIGURED";
      continue;
    }
    const probe = (adapter as { isExecutablePresent?: () => boolean }).isExecutablePresent?.();
    out[slug] = probe ? "HEALTHY" : "UNAVAILABLE";
  }
  for (const registration of MOBILE_DISABLED_REGISTRATIONS) {
    out[registration.slug] = registration.executionState;
  }
  // Burp Suite is the Prompt 8 connector; its mobile proxy capability
  // (§65) rides the same ScannerInstance discipline.
  out["burp-suite"] = "NOT_CONFIGURED";
  return out;
}

/** Async health record for the Tools API (§102). */
export async function mobileHealthRecord(
  adapters: SecurityToolAdapter[],
  deps: MobileConnectorDeps = INERT_MOBILE_DEPS,
): Promise<Map<string, MobileHealthEntry>> {
  const out = new Map<string, MobileHealthEntry>();
  for (const adapter of adapters) {
    const slug = adapter.metadata.slug;
    if ((CONNECTOR_SLUGS as readonly string[]).includes(slug)) {
      const wired = slug === "mobsf" ? !!deps.transports.mobsf : slug === "adb" ? !!deps.transports.devices : !!deps.transports.traffic;
      const health = await adapter.healthCheck().catch(() => ({ status: "NOT_CONFIGURED", detail: undefined as string | undefined }));
      out.set(slug, { slug, status: wired ? "UNKNOWN" : "NOT_CONFIGURED", detail: health.detail });
      continue;
    }
    const available = await adapter.checkAvailability().catch(() => false);
    out.set(slug, {
      slug,
      status: available ? "HEALTHY" : "UNAVAILABLE",
      ...(available ? {} : { detail: `${adapter.metadata.name} binary is not present on this host — the capability degrades honestly, never simulated (§16)` }),
    });
  }
  for (const registration of MOBILE_DISABLED_REGISTRATIONS) {
    out.set(registration.slug, { slug: registration.slug, status: registration.executionState, detail: registration.reason });
  }
  out.set("burp-suite", { slug: "burp-suite", status: "NOT_CONFIGURED", detail: "Burp Suite mobile proxy analysis rides the Prompt 8 ScannerInstance registration (§65)" });
  return out;
}
