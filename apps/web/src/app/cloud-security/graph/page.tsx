"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Cloud asset graph + risk paths (Prompt 14 §85/§66). Edges exist
 * only where a provider response or a governed check supplied
 * evidence — the graph never speculates. Risk paths are defensive
 * MODELS of exposure (public endpoint → workload → identity →
 * sensitive resource): they are never executed and privilege
 * escalation is never attempted (§67).
 */
interface EdgeRow {
  id: string; fromType: string; fromRef: string; toType: string; toRef: string;
  relationship: string; evidence?: string | null;
}
interface PathRow {
  id: string; title: string; confidence: string;
  steps: Array<{ kind?: string; ref?: string; label?: string }>; findingIds: string[];
}

function GraphInner() {
  const searchParams = useSearchParams();
  const accountId = searchParams.get("accountId") ?? "";
  const [edges, setEdges] = useState<EdgeRow[]>([]);
  const [paths, setPaths] = useState<PathRow[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const qs = accountId ? `?accountId=${accountId}` : "";
      const [g, p] = await Promise.all([
        apiFetch<{ edges: EdgeRow[] }>(`/cloud/graph${qs}`),
        apiFetch<{ items: PathRow[] }>(`/cloud/risk-paths${qs}`),
      ]);
      setEdges(g.edges ?? []);
      setPaths(p.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [accountId]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Cloud Graph" title="Asset Graph & Risk Paths" body="Evidence-backed relationships between accounts, resources, identities and workloads — plus the defensive risk paths assembled from them." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Risk paths (§66)</h2>
        {paths.length === 0 && <EmptyState title="No risk paths assembled" body="Risk paths appear when public exposure, identity privilege and sensitive resources chain together in one account's evidence." />}
        <div className="divide-y divide-slate-800">
          {paths.map((p) => (
            <div key={p.id} className="py-2 text-sm">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-slate-200">{p.title}</span>
                <Badge>confidence {p.confidence}</Badge>
                <span className="text-slate-500">{p.findingIds.length} findings</span>
              </div>
              <p className="mt-1 font-mono text-xs text-slate-500">{(p.steps ?? []).map((s) => s.label ?? s.ref ?? s.kind ?? "").filter(Boolean).join(" → ")}</p>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Relationships ({edges.length})</h2>
        {edges.length === 0 && <p className="text-sm text-slate-500">No relationships recorded yet — inventory connectors record the edges provider responses support.</p>}
        <div className="divide-y divide-slate-800">
          {edges.map((e) => (
            <div key={e.id} className="flex flex-wrap items-center gap-2 py-2 font-mono text-xs text-slate-300">
              <span>{e.fromType}:{e.fromRef}</span>
              <span className="text-cyan-300">—{e.relationship}→</span>
              <span>{e.toType}:{e.toRef}</span>
              {e.evidence && <span className="ml-auto max-w-md truncate font-sans text-slate-500">{e.evidence}</span>}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-slate-400">Loading…</p>}>
      <GraphInner />
    </Suspense>
  );
}
