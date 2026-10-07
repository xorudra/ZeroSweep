"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

type Policy = Record<string, unknown> & { hardLimits?: Record<string, number>; defaultBudget?: Record<string, number>; allowedValidators?: string[] };
type Switch = Record<string, unknown> & { id: string };

/**
 * Validation policy configuration (Prompt 16 §77) + kill switches
 * (§43). Administrator hard limits override every lower layer (§41) —
 * the API clamps them to the platform ceiling. Production default is
 * SAFE_ONLY; LAB intrusive validation requires an explicit opt-in and
 * still runs no exploit modules (§63).
 */
export default function Page() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [switches, setSwitches] = useState<Switch[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [ksLevel, setKsLevel] = useState("WORKSPACE");
  const [ksScope, setKsScope] = useState("");
  const [ksReason, setKsReason] = useState("");

  const load = useCallback(async () => {
    try {
      setPolicy(await apiFetch<Policy>("/validations/policy"));
      setSwitches(await apiFetch<Switch[]>("/validations/kill-switches"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load validation policy.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const save = async (patch: Record<string, unknown>) => {
    setNotice(null);
    try {
      const updated = await apiFetch<Policy>("/validations/policy", { method: "PUT", body: JSON.stringify(patch) });
      setPolicy(updated);
      setNotice("Policy saved.");
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Save failed.");
    }
  };

  const activate = async () => {
    setNotice(null);
    try {
      await apiFetch("/validations/kill-switches", { method: "POST", body: JSON.stringify({ level: ksLevel, scopeRef: ksScope || undefined, reason: ksReason || undefined }) });
      setNotice("Kill switch activated — matching validation sessions terminate (§43).");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Activation failed.");
    }
  };

  const clear = async (id: string) => {
    try {
      await apiFetch(`/validations/kill-switches/${id}/clear`, { method: "POST", body: JSON.stringify({}) });
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Clear failed.");
    }
  };

  if (error) return <EmptyState title="Policy unavailable" body={error} />;
  if (!policy) return <p className="text-sm text-slate-400">Loading…</p>;

  const hl = policy.hardLimits ?? {};
  const db = policy.defaultBudget ?? {};

  return (
    <>
      <PageHeader eyebrow="Security Validation" title="Validation Policy" body="Workspace defaults for controlled validation. Only MANAGE_VALIDATION_POLICY holders can change these." />
      {notice ? <p className="mb-4 rounded bg-slate-900 px-3 py-2 text-sm text-slate-200">{notice}</p> : null}

      <Card>
        <h2 className="mb-3 text-base font-semibold text-slate-100">Production policy (§64)</h2>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          <label className="text-sm text-slate-300">Production policy
            <select className="mt-1 w-full rounded bg-slate-900 px-2 py-2 text-slate-200" value={String(policy.productionPolicy ?? "SAFE_ONLY")} onChange={(e) => void save({ productionPolicy: e.target.value })}>
              <option value="SAFE_ONLY">SAFE_ONLY (default)</option>
              <option value="SAFE_AND_LOW_IMPACT_WITH_APPROVAL">SAFE + LOW_IMPACT with approval</option>
            </select>
          </label>
          <label className="text-sm text-slate-300">Default risk level
            <select className="mt-1 w-full rounded bg-slate-900 px-2 py-2 text-slate-200" value={String(policy.defaultRiskLevel ?? "SAFE")} onChange={(e) => void save({ defaultRiskLevel: e.target.value })}>
              <option value="SAFE">SAFE</option>
              <option value="LOW_IMPACT">LOW_IMPACT</option>
              <option value="REVIEW_REQUIRED">REVIEW_REQUIRED</option>
            </select>
          </label>
          <label className="text-sm text-slate-300">Approval TTL (minutes)
            <input type="number" className="mt-1 w-full rounded bg-slate-900 px-2 py-2 text-slate-200" defaultValue={Number(policy.approvalTtlMinutes ?? 60)} onBlur={(e) => void save({ approvalTtlMinutes: Number(e.target.value) })} />
          </label>
          <label className="text-sm text-slate-300">Default timeout (seconds)
            <input type="number" className="mt-1 w-full rounded bg-slate-900 px-2 py-2 text-slate-200" defaultValue={Number(policy.defaultTimeoutSeconds ?? 300)} onBlur={(e) => void save({ defaultTimeoutSeconds: Number(e.target.value) })} />
          </label>
          <label className="text-sm text-slate-300">Evidence retention (days)
            <input type="number" className="mt-1 w-full rounded bg-slate-900 px-2 py-2 text-slate-200" defaultValue={Number(policy.evidenceRetentionDays ?? 365)} onBlur={(e) => void save({ evidenceRetentionDays: Number(e.target.value) })} />
          </label>
        </div>
        <div className="mt-4 space-y-2 text-sm text-slate-300">
          <label className="flex items-center gap-2"><input type="checkbox" checked={Boolean(policy.separationOfDuties)} onChange={(e) => void save({ separationOfDuties: e.target.checked })} /> Separation of duties — requester cannot approve their own higher-risk validation (§11)</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={Boolean(policy.allowIntrusiveInLab)} onChange={(e) => void save({ allowIntrusiveInLab: e.target.checked })} /> Allow INTRUSIVE-CLASS approval flow in explicitly-marked LAB only (§63 — no exploit modules exist; architecture only)</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={Boolean(policy.callbackEnabled)} onChange={(e) => void save({ callbackEnabled: e.target.checked })} /> Controlled callback service enabled (§47)</label>
        </div>
        <p className="mt-4 text-xs text-slate-500">
          Administrator hard limits (override all layers, §41): {hl.maxRequests ?? "—"} requests · {hl.maxDurationSeconds ?? "—"}s · concurrency {hl.maxConcurrency ?? "—"} · {hl.maxBytes ?? "—"} bytes · {hl.maxRedirects ?? "—"} redirects · {hl.maxEndpoints ?? "—"} endpoints · {hl.maxTargets ?? "—"} targets.
          Default budget: {db.maxRequests ?? "—"} requests · {db.maxDurationSeconds ?? "—"}s.
        </p>
        <p className="mt-1 text-xs text-slate-500">Allowed validators: {(policy.allowedValidators ?? []).length ? (policy.allowedValidators ?? []).join(", ") : "all governed SAFE validators"}</p>
      </Card>

      <h2 className="mb-2 mt-6 text-lg font-semibold text-slate-100">Kill switches (§43)</h2>
      <Card>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm text-slate-300">Level
            <select className="mt-1 block rounded bg-slate-900 px-2 py-2 text-slate-200" value={ksLevel} onChange={(e) => setKsLevel(e.target.value)}>
              {["GLOBAL", "ORGANIZATION", "WORKSPACE", "SCAN", "TARGET", "SESSION"].map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </label>
          <label className="text-sm text-slate-300">Scope reference (for SCAN/TARGET/SESSION)
            <input className="mt-1 block rounded bg-slate-900 px-2 py-2 text-slate-200" value={ksScope} onChange={(e) => setKsScope(e.target.value)} />
          </label>
          <label className="flex-1 text-sm text-slate-300">Reason
            <input className="mt-1 block w-full rounded bg-slate-900 px-2 py-2 text-slate-200" value={ksReason} onChange={(e) => setKsReason(e.target.value)} />
          </label>
          <button onClick={() => void activate()} className="rounded bg-rose-800 px-3 py-2 text-sm text-white hover:bg-rose-700">Activate</button>
        </div>
        <div className="mt-4 space-y-2">
          {switches.length === 0 ? <p className="text-sm text-slate-400">No kill switches recorded.</p> : switches.map((s) => (
            <div key={s.id} className="flex flex-wrap items-center gap-2 text-sm text-slate-200">
              <Badge>{String(s.level ?? "")}</Badge>
              {s.scopeRef ? <span className="font-mono text-xs">{String(s.scopeRef)}</span> : null}
              <span>{s.active ? "ACTIVE" : "cleared"}</span>
              {s.reason ? <span className="text-slate-400">{String(s.reason)}</span> : null}
              {s.active ? <button onClick={() => void clear(s.id)} className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700">Clear</button> : null}
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}
