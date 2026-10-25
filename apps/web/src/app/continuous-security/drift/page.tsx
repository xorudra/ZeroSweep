"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Security drift (Prompt 22 §83). Asset, finding and risk drift plus
 * attack-surface changes, comparable by domain. New assets are
 * DISCOVERED — drift never auto-authorizes them for intrusive
 * testing (§35), and KEV/EPSS movement re-scores findings WITHOUT
 * re-scanning (§50).
 */
interface DriftBundle {
  driftEvents: Array<{ id: string; domain: string; changeType: string; entityKey: string; detail: string; detectedAt: string }>;
  findingDrift: Array<{ id: string; type: string; fingerprint: string; detail: string; detectedAt: string }>;
  riskDrift: Array<{ id: string; type: string; cve?: string | null; detail: string; detectedAt: string }>;
  attackSurfaceChanges: Array<{ id: string; type: string; host: string; priority: string; detail: string; detectedAt: string }>;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [bundle, setBundle] = useState<DriftBundle | null>(null);
  const [domain, setDomain] = useState("");
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const q = domain ? `?domain=${encodeURIComponent(domain)}` : "";
      const d = await apiFetch<DriftBundle>(`/drift${q}`);
      setBundle(d);
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load drift");
      setState("error");
    }
  }, [domain]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Continuous Security" title="Security Drift" body="What changed between immutable snapshots — assets, findings, exposure and risk." />
      <div className="flex items-center gap-2">
        <label className="text-sm text-slate-400">Domain</label>
        <select className={inputCls} value={domain} onChange={(e) => setDomain(e.target.value)}>
          <option value="">All</option>
          <option value="ASSET">Asset</option>
          <option value="WEB">Web</option>
          <option value="API">API</option>
          <option value="CLOUD">Cloud</option>
          <option value="KUBERNETES">Kubernetes</option>
          <option value="SOURCE">Source</option>
          <option value="MOBILE">Mobile</option>
          <option value="BINARY">Binary</option>
          <option value="IDENTITY">Identity</option>
          <option value="WIRELESS">Wireless</option>
        </select>
      </div>
      {state === "loading" ? <p className="text-slate-400">Loading…</p> : null}
      {state === "error" ? <EmptyState title="Could not load" body={error} /> : null}
      {state === "ready" && bundle ? (
        <>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Attack-surface changes</h3>
            {bundle.attackSurfaceChanges.length === 0 ? <EmptyState title="No surface changes" body="New ports, services, endpoints and exposure changes will appear here." /> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {bundle.attackSurfaceChanges.map((c) => (
                  <li key={c.id} className="flex flex-wrap items-center gap-2">
                    <Badge>{c.type}</Badge>
                    {c.priority === "HIGH" ? <Badge>HIGH</Badge> : null}
                    <span className="text-slate-100">{c.host}</span>
                    <span className="text-slate-400">{c.detail}</span>
                    <span className="text-slate-500">{new Date(c.detectedAt).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Finding drift</h3>
            {bundle.findingDrift.length === 0 ? <p className="text-sm text-slate-500">No finding drift recorded.</p> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {bundle.findingDrift.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center gap-2">
                    <Badge>{e.type}</Badge>
                    <span className="font-mono text-xs">{e.fingerprint.slice(0, 12)}…</span>
                    <span className="text-slate-400">{e.detail}</span>
                    <span className="text-slate-500">{new Date(e.detectedAt).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Risk drift (intelligence movement — no re-scan)</h3>
            {bundle.riskDrift.length === 0 ? <p className="text-sm text-slate-500">No risk drift recorded. KEV additions and EPSS/CVSS movement land here and re-score affected findings.</p> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {bundle.riskDrift.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center gap-2">
                    <Badge>{e.type}</Badge>
                    <span className="text-slate-100">{e.cve ?? ""}</span>
                    <span className="text-slate-400">{e.detail}</span>
                    <span className="text-slate-500">{new Date(e.detectedAt).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Domain drift events</h3>
            {bundle.driftEvents.length === 0 ? <p className="text-sm text-slate-500">No generic drift events recorded.</p> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {bundle.driftEvents.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center gap-2">
                    <Badge>{e.domain}</Badge>
                    <span className="text-slate-100">{e.changeType}</span>
                    <span className="text-slate-400">{e.detail}</span>
                    <span className="text-slate-500">{new Date(e.detectedAt).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      ) : null}
    </div>
  );
}
