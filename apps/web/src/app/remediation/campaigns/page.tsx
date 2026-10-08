"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface Progress { total: number; assigned: number; inProgress: number; fixClaimed: number; verificationPending: number; verified: number; closed: number; overdue: number; exceptions: number; pctVerified: number }
interface CampaignRow { campaign: { id: string; name: string; status: string; scope: Record<string, unknown> }; progress: Progress }

/**
 * Remediation campaigns (Prompt 31 §107). One CVE / dependency /
 * technology push across assets; progress is computed from live case
 * states every load — never stored counters.
 */
export default function Page() {
  const [rows, setRows] = useState<CampaignRow[]>([]);
  const [name, setName] = useState("");
  const [cve, setCve] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(() => {
    apiFetch<CampaignRow[]>("/remediation/campaigns").then(setRows).catch(() => setRows([]));
  }, []);
  useEffect(load, [load]);

  const create = async () => {
    try {
      await apiFetch("/remediation/campaigns", {
        method: "POST",
        body: JSON.stringify({ name, scope: cve ? { cve } : {} }),
      });
      setMessage("Campaign created and matching cases collected.");
      load();
    } catch (e) {
      setMessage((e as Error).message);
    }
  };

  return (
    <>
      <PageHeader eyebrow="Remediation" title="Campaigns" body="Coordinated pushes — a KEV listing, a vulnerable dependency, a fleet-wide misconfiguration — tracked from assignment to verified closure." />
      {message && <p className="mb-3 text-sm text-amber-300">{message}</p>}
      <Card>
        <div className="mb-4 flex gap-2">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Campaign name" className="rounded bg-slate-800 px-2 py-1 text-sm" />
          <input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE (optional scope)" className="rounded bg-slate-800 px-2 py-1 text-sm" />
          <button onClick={create} className="rounded bg-sky-700 px-3 py-1 text-sm text-white">Create campaign</button>
        </div>
        {rows.length === 0 ? (
          <EmptyState title="No campaigns" body="Create a campaign scoped to a CVE, component or KEV push; matching canonical findings are collected automatically." />
        ) : (
          <ul className="space-y-4">
            {rows.map(({ campaign, progress }) => (
              <li key={campaign.id} className="border-b border-slate-800 pb-3">
                <div className="flex items-baseline justify-between">
                  <span className="font-medium">{campaign.name}</span>
                  <span className="text-sm text-slate-400">{progress.pctVerified}% verified · {progress.total} cases</span>
                </div>
                <div className="mt-1 h-2 w-full rounded bg-slate-800">
                  <div className="h-2 rounded bg-emerald-600" style={{ width: `${progress.pctVerified}%` }} />
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  assigned {progress.assigned} · in progress {progress.inProgress} · fix claimed {progress.fixClaimed} ·
                  verifying {progress.verificationPending} · verified {progress.verified} · closed {progress.closed} ·
                  overdue {progress.overdue} · exceptions {progress.exceptions}
                </p>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
