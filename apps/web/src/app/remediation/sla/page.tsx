"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface SlaDash { byState: Record<string, number>; byTeam: Record<string, { total: number; breached: number }>; total: number }
interface Policy { id: string; name: string; version: number; isDefault: boolean; active: boolean; rules: Record<string, number> }

/**
 * SLA management (Prompt 31 §106). Policies are configuration — never
 * hardcoded; every edit is a new version and snapshots keep the
 * version they were resolved under.
 */
export default function Page() {
  const [dash, setDash] = useState<SlaDash | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [name, setName] = useState("");
  const [hours, setHours] = useState("72");
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(() => {
    apiFetch<SlaDash>("/remediation/sla").then(setDash).catch(() => setDash(null));
    apiFetch<Policy[]>("/remediation/sla/policies").then(setPolicies).catch(() => setPolicies([]));
  }, []);
  useEffect(load, [load]);

  const create = async () => {
    try {
      await apiFetch("/remediation/sla/policies", {
        method: "POST",
        body: JSON.stringify({ name, rules: { P1: Number(hours), CRITICAL: Number(hours) } }),
      });
      setMessage("Policy created (version 1).");
      load();
    } catch (e) {
      setMessage((e as Error).message);
    }
  };

  return (
    <>
      <PageHeader eyebrow="Remediation" title="SLA Management" body="States derive from stored timestamps and policy versions — paused time never counts against the target, and recalculation never silently shortens a due date." />
      {message && <p className="mb-3 text-sm text-amber-300">{message}</p>}
      {dash && (
        <div className="mb-4 grid grid-cols-3 gap-3 md:grid-cols-6">
          {Object.entries(dash.byState).map(([state, n]) => (
            <Card key={state}>
              <div className="text-2xl font-semibold">{n}</div>
              <div className="text-xs text-slate-400">{state}</div>
            </Card>
          ))}
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <h3 className="mb-2 text-sm font-semibold">Policies</h3>
          {policies.length === 0 ? <p className="text-sm text-slate-400">No policies configured — cases get no due date until one exists (never an invented date).</p> : (
            <ul className="space-y-2 text-sm">
              {policies.map((p) => (
                <li key={p.id} className="border-b border-slate-800 pb-2">
                  <span className="font-medium">{p.name}</span> <span className="text-slate-500">v{p.version}{p.isDefault ? " · default" : ""}{p.active ? "" : " · inactive"}</span>
                  <div className="text-slate-400">{Object.entries(p.rules).map(([k, v]) => `${k}: ${v}h`).join(" · ")}</div>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-4 flex gap-2">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Policy name" className="rounded bg-slate-800 px-2 py-1 text-sm" />
            <input value={hours} onChange={(e) => setHours(e.target.value)} placeholder="P1 hours" className="w-24 rounded bg-slate-800 px-2 py-1 text-sm" />
            <button onClick={create} className="rounded bg-sky-700 px-3 py-1 text-sm text-white">Create policy</button>
          </div>
        </Card>
        <Card>
          <h3 className="mb-2 text-sm font-semibold">By team</h3>
          {dash && Object.keys(dash.byTeam).length ? (
            <ul className="space-y-1 text-sm">
              {Object.entries(dash.byTeam).map(([team, v]) => (
                <li key={team}>{team}: {v.total} tracked · <span className={v.breached ? "text-red-300" : ""}>{v.breached} breached</span></li>
              ))}
            </ul>
          ) : <p className="text-sm text-slate-400">No SLA snapshots yet.</p>}
        </Card>
      </div>
    </>
  );
}
