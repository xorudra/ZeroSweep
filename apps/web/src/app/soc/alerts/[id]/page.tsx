"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Alert detail (Prompt 28 §104): the triggering evidence (matched
 * telemetry events), detection context, ATT&CK techniques as context
 * only, triage workflow (§37) and escalation to an incident (§41).
 */
interface AlertDetail {
  alert: Record<string, unknown>;
  matches: Array<Record<string, unknown>>;
  triage: Array<Record<string, unknown>>;
  rule: (Record<string, unknown> & { attackMappings?: unknown }) | null;
  asset: Record<string, unknown> | null;
  finding: Record<string, unknown> | null;
  indicator: Record<string, unknown> | null;
}

const DECISIONS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_POSITIVE", "DUPLICATE", "NEEDS_INVESTIGATION", "ESCALATED"];

export default function Page() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<AlertDetail | null>(null);
  const [decision, setDecision] = useState("TRUE_POSITIVE");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<AlertDetail>(`/soc/alerts/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const triage = async () => {
    try {
      await apiFetch(`/soc/alerts/${params.id}/triage`, { method: "POST", body: JSON.stringify({ decision, reason: reason || undefined }) });
      setNotice("Triage recorded.");
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Triage failed."); }
  };

  const escalate = async () => {
    try {
      const out = await apiFetch<Record<string, unknown>>(`/soc/alerts/${params.id}/escalate`, { method: "POST", body: JSON.stringify({}) });
      setNotice(`Escalated to incident ${String(out.id)}. See the Incidents queue.`);
    } catch (e) { setError(e instanceof ApiError ? e.message : "Escalation failed."); }
  };

  const a = data?.alert;
  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Security Operations" title={a ? String(a.title) : "Alert"} body="Triggering evidence and triage workflow." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      {a && (
        <Card title="Alert">
          <div className="flex flex-wrap gap-2 text-xs">
            <Badge>{String(a.priority)}</Badge><Badge>{String(a.severity)}</Badge><Badge>{String(a.status)}</Badge>
            <Badge>confidence: {String(a.confidence ?? "—")}</Badge>
            <span className="text-slate-400">priority score {String(a.priorityScore ?? "—")} · occurrences {String(a.occurrenceCount)}</span>
            {Boolean(a.slaBreached) && <span className="text-red-400">SLA BREACHED</span>}
          </div>
          <p className="mt-3 whitespace-pre-wrap text-sm text-slate-300">{String(a.description ?? "")}</p>
          <p className="mt-2 text-xs text-slate-500">
            First seen {new Date(String(a.firstSeen)).toLocaleString()} · last seen {new Date(String(a.lastSeen)).toLocaleString()}
            {a.assetId ? <> · asset {String(a.assetId)}</> : null}
            {a.identityReference ? <> · identity {String(a.identityReference)}</> : null}
          </p>
          {Array.isArray(a.priorityFactors) && (
            <p className="mt-2 text-xs text-slate-500">Priority factors: {(a.priorityFactors as Array<Record<string, unknown>>).map((f) => `${String(f.name)} +${String(f.points)}`).join(", ")}</p>
          )}
        </Card>
      )}
      <Card title="Triggering evidence — matched telemetry (§35)">
        {!data || data.matches.length === 0 ? <EmptyState title="No detection matches recorded for this alert." body="" /> : (
          <ul className="space-y-2 text-sm">
            {data.matches.map((m) => (
              <li key={String(m.id)} className="rounded bg-slate-800/60 p-2">
                <span className="text-slate-200">{String(m.reason)}</span>
                <span className="block text-xs text-slate-500">confidence {String(m.confidence)} · events {(m.eventIds as string[]).join(", ")}</span>
              </li>
            ))}
          </ul>
        )}
        {data?.indicator && <p className="mt-2 text-sm text-amber-300">Matched indicator: {String(data.indicator.type)} {String(data.indicator.valueNormalized)} (confidence {String(data.indicator.confidence)}) — provenance is on the match record; a match is context, not attribution.</p>}
      </Card>
      <div className="grid gap-6 md:grid-cols-2">
        <Card title="Triage (§37)">
          <div className="space-y-2">
            <select className="w-full rounded bg-slate-800 px-2 py-1 text-sm" value={decision} onChange={(e) => setDecision(e.target.value)}>
              {DECISIONS.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
            <input className="w-full rounded bg-slate-800 px-2 py-1 text-sm" placeholder="Reason (recorded on the triage row)" value={reason} onChange={(e) => setReason(e.target.value)} />
            <div className="flex gap-2">
              <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white" onClick={triage}>Record triage</button>
              <button className="rounded bg-red-700 px-3 py-1 text-sm text-white" onClick={escalate}>Escalate to incident</button>
            </div>
            {data && data.triage.length > 0 && (
              <ul className="text-xs text-slate-400">
                {data.triage.map((t) => <li key={String(t.id)}>{String(t.decision)} by {String(t.analystId)} — {String(t.reason ?? "")}</li>)}
              </ul>
            )}
          </div>
        </Card>
        <Card title="Detection context">
          {data?.rule ? (
            <div className="text-sm text-slate-300">
              <p>{String(data.rule.name)} · v{String(data.rule.currentVersion)} · {String(data.rule.status)}</p>
              <p className="mt-1 text-xs text-slate-500">MITRE ATT&CK mappings are technique context for analysts — a mapping never asserts an adversary performed the technique (§26).</p>
              <pre className="mt-2 max-h-40 overflow-auto rounded bg-slate-900 p-2 text-xs">{JSON.stringify(data.rule.attackMappings ?? [], null, 2)}</pre>
              <Link className="text-xs text-indigo-300 hover:underline" href="/soc/detections">Open detection management</Link>
            </div>
          ) : <EmptyState title="No detection rule attached (correlation or indicator alert)." body="" />}
        </Card>
      </div>
    </div>
  );
}
