"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch } from "@/lib/api-client";
import { Badge, Card } from "@dsrclone/ui";

/**
 * Proxy scanner connector panel (Prompt 8 §56): ZAP / Burp / Caido are
 * INTERACTIVE CONNECTORS, not CLI tools — they run against scanner
 * instances an administrator registers (Settings → Scanner Instances).
 * This panel shows the honest configuration state for the caller's
 * organization: NOT_CONFIGURED when nothing is registered (never a fake
 * "healthy"), otherwise each instance's deployment, health, version,
 * license state and detected capabilities. Secrets are never shown —
 * instances carry credential REFERENCE names only (§20).
 */

export const PROXY_SLUGS = ["owasp-zap", "burp-suite-professional", "caido"];

interface InstanceView {
  id: string;
  toolSlug: string;
  name: string;
  endpointReference: string;
  deploymentType: string;
  credentialReference?: string | null;
  declaredCapabilities?: string[];
  detectedCapabilities?: string[];
  healthStatus: string;
  version?: string | null;
  licenseState?: string | null;
  lastHealthCheckAt?: string | null;
  lastHealthDetail?: string | null;
  enabled: boolean;
}

interface HealthView {
  slug: string;
  healthStatus: string;
  configuredInstances?: number;
  detail?: string;
  source?: string;
}

function healthTone(status: string): string {
  if (status === "HEALTHY") return "text-emerald-300";
  if (status === "DEGRADED") return "text-amber-300";
  if (status === "NOT_CONFIGURED") return "text-slate-400";
  return "text-red-300";
}

export function ScannerConnectorPanel({ slug }: { slug: string }) {
  const [instances, setInstances] = useState<InstanceView[] | null>(null);
  const [health, setHealth] = useState<HealthView | null>(null);
  const [forbidden, setForbidden] = useState(false);

  useEffect(() => {
    let cancelled = false;
    apiFetch<HealthView>(`/tools/${slug}/health`).then((h) => { if (!cancelled) setHealth(h); }).catch(() => undefined);
    apiFetch<InstanceView[]>("/scanners/instances")
      .then((rows) => { if (!cancelled) setInstances(rows.filter((r) => r.toolSlug === slug)); })
      .catch(() => { if (!cancelled) setForbidden(true); });
    return () => { cancelled = true; };
  }, [slug]);

  return (
    <Card title="Interactive scanner connector (Prompt 8)">
      <p className="text-sm text-slate-400">
        This product integrates as a <strong className="text-slate-200">connector</strong>, not a command-line tool:
        ZeroSweep talks to an administrator-registered scanner instance over its API, inside an isolated
        per-assessment context locked to the approved scope. Passive analysis and issue/endpoint import are the
        default; <strong className="text-slate-200">active scanning is INTRUSIVE, disabled by default</strong>, and
        requires a separate, expiring approval (verified target + approved scope + approved assessment + budget).
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-3 text-sm">
        <span className="text-slate-500">Connector health:</span>
        <span className={healthTone(health?.healthStatus ?? "NOT_CONFIGURED")}>
          {health?.healthStatus ?? "NOT_CONFIGURED"}
        </span>
        {typeof health?.configuredInstances === "number" ? (
          <span className="text-slate-400">{health.configuredInstances} configured instance{health.configuredInstances === 1 ? "" : "s"}</span>
        ) : null}
        <Link href="/settings/scanners" className="text-sky-300 hover:underline">Manage scanner instances →</Link>
      </div>
      {health?.detail ? <p className="mt-1 text-xs text-slate-500">{health.detail}</p> : null}

      {forbidden ? (
        <p className="mt-3 text-sm text-slate-500">
          Instance details are visible to Owner/Admin/Security Engineer roles. Ask an administrator to register or
          health-check this connector under Settings → Scanner Instances.
        </p>
      ) : instances === null ? (
        <p className="mt-3 text-sm text-slate-500">Loading instances…</p>
      ) : instances.length === 0 ? (
        <p className="mt-3 text-sm text-amber-300">
          NOT_CONFIGURED — no instance of this scanner is registered for your organization. The passive-analysis
          stage will be honestly skipped in scans until an administrator registers one.
        </p>
      ) : (
        <div className="mt-3 space-y-3">
          {instances.map((inst) => (
            <div key={inst.id} className="rounded-lg border border-slate-800 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-slate-200">{inst.name}</span>
                <Badge>{inst.deploymentType}</Badge>
                <span className={`text-sm ${healthTone(inst.healthStatus)}`}>{inst.healthStatus}</span>
                {!inst.enabled ? <Badge>DISABLED</Badge> : null}
              </div>
              <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-400 md:grid-cols-3">
                <div>Endpoint reference: <span className="text-slate-200">{inst.endpointReference}</span></div>
                <div>Credential: <span className="text-slate-200">{inst.credentialReference ? `reference “${inst.credentialReference}” (value in vault, never shown)` : "none"}</span></div>
                <div>Version: <span className="text-slate-200">{inst.version ?? "not probed yet"}</span></div>
                <div>License: <span className="text-slate-200">{inst.licenseState ?? "—"}</span></div>
                <div>Last health check: <span className="text-slate-200">{inst.lastHealthCheckAt ? new Date(inst.lastHealthCheckAt).toLocaleString() : "never"}</span></div>
                <div>Detected capabilities: <span className="text-slate-200">{(inst.detectedCapabilities ?? []).join(", ") || "—"}</span></div>
              </dl>
              {inst.lastHealthDetail ? <p className="mt-1 text-xs text-slate-500">{inst.lastHealthDetail}</p> : null}
            </div>
          ))}
        </div>
      )}
      <p className="mt-3 text-xs text-slate-500">
        Scanner endpoints are resolved from server configuration by reference name — the API never accepts a
        scanner URL from a client, which keeps this surface SSRF-safe. Burp Suite is commercial: the administrator
        supplies the licensed environment; ZeroSweep never redistributes it.
      </p>
    </Card>
  );
}
