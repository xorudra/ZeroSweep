"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/** Control dashboard (Prompt 26 §78): owner, implementation,
 *  effectiveness, last evaluation, mapped frameworks. Technical
 *  controls are evaluated from live platform signals; administrative
 *  controls require manual evidence and human review. */
interface ControlRow {
  id: string; code: string; title: string; controlType: string; implementationType: string;
  implementationStatus: string; effectiveness: string;
  owners: Array<{ ownerType: string; ownerRef: string }>;
  mappingCount: number;
  lastEvaluation: { result: string; confidence: string; evaluatedAt: string } | null;
}

export default function Page() {
  const [items, setItems] = useState<ControlRow[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: ControlRow[] }>("/grc/controls");
      setItems(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const evaluate = async (id: string) => {
    setBusy(id);
    try {
      await apiFetch(`/grc/controls/${id}/evaluate`, { method: "POST", body: "{}" });
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Evaluation failed.");
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="GRC · Controls" title="Control Library" body="DSRclone's normalized controls. A control with no current evidence evaluates INCONCLUSIVE — never a pass by default." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <Card>
        {items.length === 0 ? (
          <EmptyState title="No controls yet" body="The control library seeds automatically on first use." />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="py-1">Control</th><th>Type</th><th>Owner</th><th>Implementation</th>
                <th>Effectiveness</th><th>Last evaluation</th><th>Frameworks</th><th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => (
                <tr key={c.id} className="border-t border-slate-800">
                  <td className="py-2 pr-2"><span className="font-medium">{c.code}</span><br /><span className="text-slate-400">{c.title}</span></td>
                  <td className="pr-2">{c.controlType} / {c.implementationType}</td>
                  <td className="pr-2">{c.owners[0] ? `${c.owners[0].ownerType}:${c.owners[0].ownerRef}` : "—"}</td>
                  <td className="pr-2"><Badge>{c.implementationStatus}</Badge></td>
                  <td className="pr-2">{c.effectiveness}</td>
                  <td className="pr-2">{c.lastEvaluation ? `${c.lastEvaluation.result} (${c.lastEvaluation.confidence})` : "NOT_TESTED"}</td>
                  <td className="pr-2">{c.mappingCount}</td>
                  <td>
                    <button className="rounded border border-slate-700 px-2 py-1 text-xs" disabled={busy === c.id} onClick={() => void evaluate(c.id)}>
                      {busy === c.id ? "Testing…" : "Test now"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
