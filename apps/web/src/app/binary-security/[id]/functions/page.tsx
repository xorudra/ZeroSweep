"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Function explorer (Prompt 18 §87). A BOUNDED inventory view —
 * search, filter by source tool, risky-API references highlighted.
 * There is deliberately no unlimited decompiler dump (§89): this is
 * an inventory, and access is permission-gated + audited
 * (BINARY_DECOMPILATION_ACCESSED).
 */
interface FunctionRow {
  id: string; name: string; address?: string | null; size?: number | null;
  callingConvention?: string | null; fingerprint?: string | null;
  referencesRiskyApi: string[]; confidence?: number | null; source: string;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const params = useParams<{ id: string }>();
  const [functions, setFunctions] = useState<FunctionRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [riskyOnly, setRiskyOnly] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<{ items: FunctionRow[] }>(`/binaries/${params.id}/functions`);
      setFunctions(res.items);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load functions — the explorer requires the VIEW_BINARY_DECOMPILATION permission");
      setState("error");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const sources = useMemo(() => [...new Set(functions.map((f) => f.source))], [functions]);
  const visible = functions.filter((f) =>
    (sourceFilter === "ALL" || f.source === sourceFilter)
    && (!riskyOnly || f.referencesRiskyApi.length > 0)
    && (query === "" || f.name.toLowerCase().includes(query.toLowerCase())),
  );

  if (state === "loading") return <p className="text-sm text-slate-400">Loading functions…</p>;
  if (state === "error") return <p className="text-sm text-red-400">{error}</p>;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Binary Security" title="Function explorer" body="Bounded function inventory from Ghidra/radare2 static analysis. A function that REFERENCES a dangerous API is evidence for review — an import alone is never a vulnerability (§45)." />
      <Card>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm text-slate-400">Search
            <input className={`${inputCls} ml-2`} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="function name" />
          </label>
          <label className="text-sm text-slate-400">Source tool
            <select className={`${inputCls} ml-2`} value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
              <option>ALL</option>
              {sources.map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input type="checkbox" checked={riskyOnly} onChange={(e) => setRiskyOnly(e.target.checked)} />
            Risky-API references only
          </label>
          <span className="text-xs text-slate-500">{visible.length} of {functions.length} functions</span>
        </div>
      </Card>
      <Card>
        {visible.length === 0 && <EmptyState title="No functions match" body="Functions arrive with the Ghidra/radare2 static analysis stages." />}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead><tr className="text-slate-400"><th className="py-1 pr-3">Function</th><th className="py-1 pr-3">Address</th><th className="py-1 pr-3">Size</th><th className="py-1 pr-3">Risky references</th><th className="py-1 pr-3">Confidence</th><th className="py-1">Source</th></tr></thead>
            <tbody>
              {visible.map((f) => (
                <tr key={f.id} className="border-t border-slate-800">
                  <td className="py-1.5 pr-3 font-mono text-slate-200">{f.name}</td>
                  <td className="py-1.5 pr-3 font-mono text-slate-400">{f.address ?? "—"}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{f.size ?? "—"}</td>
                  <td className="py-1.5 pr-3">{f.referencesRiskyApi.length > 0 ? <Badge>{f.referencesRiskyApi.join(", ")}</Badge> : <span className="text-slate-500">—</span>}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{f.confidence ?? "—"}</td>
                  <td className="py-1.5 text-slate-400">{f.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-xs text-slate-500">Cross-build identity uses the stable function fingerprint — never the absolute address alone (§22).</p>
      </Card>
    </div>
  );
}
