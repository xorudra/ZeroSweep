/**
 * Prompt 15 — Active Directory adapter registry (§102/§103).
 *
 * Eight adapters are implemented: the LDAP + BloodHound connectors and
 * the governed CLI adapters (ldapsearch, SharpHound, PingCastle,
 * enum4linux-ng, SMBMap, Certipy-posture). The offensive tools —
 * NetExec (offensive), Impacket, Kerbrute, Responder, PowerView
 * (offensive), ADExplorer (manual) — are registered as DISABLED
 * descriptors in types.ts with NO adapter here: they can never be
 * selected by a stage, and the offensive-policy test (§112) pins that.
 * Connectors health-report NOT_CONFIGURED until a deployment wires a
 * read-only transport on an approved internal worker (§15).
 */
import type { ToolRunner } from "../recon/runner";
import { ProcessToolRunner } from "../recon/runner";
import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import {
  BloodHoundConnector, CertipyPostureAdapter, Enum4linuxNgAdapter, LdapDirectoryConnector,
  LdapsearchAdapter, PingCastleAdapter, SharpHoundAdapter, SmbMapAdapter,
} from "./adapters-directory";
import { INERT_DIRECTORY_DEPS, type DirectoryConnectorDeps } from "./inventory";
import { AD_DISABLED_REGISTRATIONS } from "./types";

export const DIRECTORY_SLUGS = {
  connectors: ["ldap-directory-connector", "bloodhound-connector"],
  cli: ["ldapsearch", "sharphound", "pingcastle", "enum4linux-ng", "smbmap", "certipy-posture"],
} as const;

export const ALL_DIRECTORY_SLUGS: string[] = [...DIRECTORY_SLUGS.connectors, ...DIRECTORY_SLUGS.cli];

/** Slugs that must NEVER be executable (§51–§56/§112): the offensive
 *  registrations + the offensive-only tool names. */
export const DIRECTORY_DISABLED_SLUGS: string[] = AD_DISABLED_REGISTRATIONS.map((r) => r.slug);

export function createDirectoryAdapters(
  runner?: ToolRunner,
  deps: DirectoryConnectorDeps = INERT_DIRECTORY_DEPS,
): SecurityToolAdapter[] {
  const r = runner ?? new ProcessToolRunner();
  return [
    new LdapDirectoryConnector(deps),
    new BloodHoundConnector(deps),
    new LdapsearchAdapter(r),
    new SharpHoundAdapter(r),
    new PingCastleAdapter(r),
    new Enum4linuxNgAdapter(r),
    new SmbMapAdapter(r),
    new CertipyPostureAdapter(r),
  ];
}

export function registerDirectoryAdapters(
  registry: ToolRegistry,
  runner?: ToolRunner,
  deps: DirectoryConnectorDeps = INERT_DIRECTORY_DEPS,
): SecurityToolAdapter[] {
  const adapters = createDirectoryAdapters(runner, deps);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/** Per-slug health for the Tools API: connectors are NOT_CONFIGURED
 *  until a transport is wired (§15); CLI adapters probe their binary;
 *  DISABLED registrations report DISABLED — visibly, not silently. */
export async function directoryHealthBySlug(
  adapters: SecurityToolAdapter[],
  deps: DirectoryConnectorDeps = INERT_DIRECTORY_DEPS,
): Promise<Map<string, { status: string; detail?: string }>> {
  const out = new Map<string, { status: string; detail?: string }>();
  const transportWired = Object.keys(deps.transports).length > 0;
  for (const adapter of adapters) {
    const slug = adapter.metadata.slug;
    if (DIRECTORY_SLUGS.connectors.includes(slug as never)) {
      out.set(slug, transportWired
        ? { status: "UNKNOWN", detail: "transport configured; per-domain health resolves at collection time" }
        : { status: "NOT_CONFIGURED", detail: "no read-only directory transport is configured in this worker — registered domains report NOT_CONFIGURED (§15)" });
      continue;
    }
    try {
      const available = await adapter.checkAvailability();
      out.set(slug, available ? { status: "AVAILABLE" } : { status: "UNAVAILABLE", detail: "binary not present on this worker" });
    } catch {
      out.set(slug, { status: "UNAVAILABLE" });
    }
  }
  for (const registration of AD_DISABLED_REGISTRATIONS) {
    out.set(registration.slug, {
      status: "DISABLED",
      detail: `${registration.classification}: ${registration.note}`,
    });
  }
  return out;
}

/** Synchronous plan-time health record (mirrors cloudSecHealthBySlug):
 *  connectors are NOT_CONFIGURED constants at plan time — per-domain
 *  configuration resolves in the worker (§15); CLI adapters use the
 *  synchronous PATH probe; DISABLED registrations report DISABLED. */
export function directoryHealthRecord(
  adapters: SecurityToolAdapter[],
  deps: DirectoryConnectorDeps = INERT_DIRECTORY_DEPS,
): Record<string, string> {
  const out: Record<string, string> = {};
  const transportWired = Object.keys(deps.transports).length > 0;
  for (const adapter of adapters) {
    const slug = adapter.metadata.slug;
    if (DIRECTORY_SLUGS.connectors.includes(slug as never)) {
      out[slug] = transportWired ? "UNKNOWN" : "NOT_CONFIGURED";
      continue;
    }
    const probe = (adapter as { isExecutablePresent?: () => boolean }).isExecutablePresent?.();
    out[slug] = probe ? "HEALTHY" : "UNAVAILABLE";
  }
  for (const registration of AD_DISABLED_REGISTRATIONS) {
    out[registration.slug] = "DISABLED";
  }
  return out;
}
