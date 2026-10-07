"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Binary diff view (Prompt 18 §90). Cross-build comparison keyed by
 * stable fingerprints: functions added/removed/changed, dependency
 * changes, hardening changes, and REGRESSIONS called out explicitly
 * (hardening removed, vulnerable dependency introduced, finding
 * reappeared).
 */
interface DiffDetail {
  id: string; baseArtifactId: string; targetArtifactId: string;
  summary: { functionsAdded: number; functionsRemoved: number; functionsChanged: number; dependenciesAdded: number; dependenciesRemoved: number; regressions: number };
  regressions: Array<{ kind: string; detail: string }>;
  detail: {
    functionsAdded: string[]; functionsRemoved: string[]; functionsChanged: string[];
    dependenciesAdded: Array<{ library: string; version?: string }>; dependenciesRemoved: Array<{ library: string; version?: string }>;
    dependenciesChanged: Array<{ library: string; from?: string; to?: string }>;
    hardeningChanges: Array<{ name: string; from: string; to: string; regression: boolean }>;
  };
  createdAt?: string | null;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [diff, setDiff] = useState<DiffDetail | null>(null);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<DiffDetail>(`/binary-diffs/${params.id}`);
      setDiff(res);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load diff");
      setState("error");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (state === "loading") return <p className="text-sm text-slate-400">Loading diff…</p>;
  if (state === "error" || !diff) return <p className="text-sm text-red-400">{error || "Diff not found"}</p>;
  const d = diff.detail;
  const s = diff.summary;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Binary Security" title="Cross-build diff" body="Base → target comparison over persisted inventories. Identity is fingerprint-based; a changed address alone is not a changed function (§22/§53)." />
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card><p className="text-2xl font-semibold text-slate-100">{s.functionsAdded}/{s.functionsRemoved}/{s.functionsChanged}</p><p className="text-sm text-slate-400">Functions added / removed / changed</p></Card>
        <Card><p className="text-2xl font-semibold text-slate-100">{s.dependenciesAdded}/{s.dependenciesRemoved}/{d.dependenciesChanged.length}</p><p className="text-sm text-slate-400">Dependencies added / removed / changed</p></Card>
        <Card><p className="text-2xl font-semibold text-slate-100">{d.hardeningChanges.length}</p><p className="text-sm text-slate-400">Hardening changes</p></Card>
        <Card><p className="text-2xl font-semibold text-red-300">{s.regressions}</p><p className="text-sm text-slate-400">Regressions</p></Card>
      </div>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Regressions</h2>
        {diff.regressions.length === 0 && <EmptyState title="No regressions" body="No hardening was removed, no vulnerable dependency was introduced, and no resolved finding reappeared." />}
        <div className="space-y-2">
          {diff.regressions.map((r, i) => (
            <div key={i} className="flex items-center justify-between gap-2 rounded bg-slate-900 px-3 py-2">
              <span className="text-sm text-slate-200">{r.detail}</span>
              <Badge>{r.kind}</Badge>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-lg font-medium text-slate-100">Function changes</h2>
          <p className="text-xs text-slate-500">Added</p>
          <p className="mb-2 font-mono text-xs text-slate-300">{d.functionsAdded.join(", ") || "—"}</p>
          <p className="text-xs text-slate-500">Removed</p>
          <p className="mb-2 font-mono text-xs text-slate-300">{d.functionsRemoved.join(", ") || "—"}</p>
          <p className="text-xs text-slate-500">Changed (fingerprint)</p>
          <p className="font-mono text-xs text-slate-300">{d.functionsChanged.join(", ") || "—"}</p>
        </Card>
        <Card>
          <h2 className="mb-3 text-lg font-medium text-slate-100">Hardening changes</h2>
          {d.hardeningChanges.length === 0 && <p className="text-sm text-slate-500">No mitigation state changed.</p>}
          <div className="space-y-1">
            {d.hardeningChanges.map((h) => (
              <div key={h.name} className="flex items-center justify-between rounded bg-slate-900 px-3 py-1.5 text-sm">
                <span className="text-slate-200">{h.name}</span>
                <span className="text-xs text-slate-400">{h.from} → {h.to}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-500">Dependencies added: {d.dependenciesAdded.map((x) => `${x.library}${x.version ? `@${x.version}` : ""}`).join(", ") || "—"} · removed: {d.dependenciesRemoved.map((x) => `${x.library}${x.version ? `@${x.version}` : ""}`).join(", ") || "—"} · changed: {d.dependenciesChanged.map((x) => `${x.library} ${x.from ?? "?"}→${x.to ?? "?"}`).join(", ") || "—"}</p>
        </Card>
      </div>
    </div>
  );
}
