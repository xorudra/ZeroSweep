"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Backup admin (Prompt 38 §200): backup history, status, retention and
 * restore tests. A backup is operationally valid only after a restore
 * test (§175). Restores are OWNER-only, require the typed
 * confirmation, verify the checksum before writing anything (§234),
 * and can only target an isolated recovery database (§173) — this
 * page cannot restore over production.
 */
interface BackupRow {
  id: string; kind: string; status: string; sizeBytes: string | null; durationMs: number | null;
  checksumSha256: string | null; encrypted: boolean; retentionExpiresAt: string | null;
  startedAt: string; errorSummary: string | null;
}
interface RestoreRow { id: string; status: string; targetDatabase: string; isRestoreTest: boolean; startedAt: string; errorSummary: string | null }

export default function Page() {
  const [items, setItems] = useState<BackupRow[]>([]);
  const [restores, setRestores] = useState<Record<string, RestoreRow[]>>({});
  const [target, setTarget] = useState("zerosweep_restore");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: BackupRow[] }>("/platform/backups");
      setItems(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const start = async () => {
    setBusy(true);
    try {
      const rec = await apiFetch<BackupRow>("/platform/backups", { method: "POST", body: JSON.stringify({ kind: "POSTGRES" }) });
      setNotice(`backup ${rec.id} finished with status ${rec.status}`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Backup could not be started.");
    } finally { setBusy(false); }
  };

  const showRestores = async (id: string) => {
    try {
      const data = await apiFetch<{ items: RestoreRow[] }>(`/platform/backups/${id}/restores`);
      setRestores((r) => ({ ...r, [id]: data.items ?? [] }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load restores.");
    }
  };

  const restore = async (id: string) => {
    setBusy(true);
    try {
      const rec = await apiFetch<RestoreRow>(`/platform/backups/${id}/restore`, {
        method: "POST",
        body: JSON.stringify({ targetDatabase: target, confirm, isRestoreTest: true }),
      });
      setNotice(`restore ${rec.id} finished with status ${rec.status}${rec.errorSummary ? ` — ${rec.errorSummary}` : ""}`);
      await showRestores(id);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Restore was refused.");
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Platform Operations" title="Backups" body="Platform backups and restore tests. Creation alone does not prove a backup works — run a restore test into an isolated recovery database (§175)." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {notice && <p className="rounded bg-emerald-950/60 px-3 py-2 text-sm text-emerald-300">{notice}</p>}
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <button disabled={busy} className="rounded bg-sky-700 px-3 py-1.5 text-sm text-white disabled:opacity-50" onClick={() => void start()}>
            Start PostgreSQL backup
          </button>
          <span className="text-sm text-slate-400">Logical dump (pg_dump), checksum-recorded, encrypted when an operator passphrase file is configured (§166).</span>
        </div>
      </Card>
      <Card>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <label className="text-slate-400">restore target (isolated DB)
            <input className="ml-2 rounded bg-slate-900 px-2 py-1 text-slate-200" value={target} onChange={(e) => setTarget(e.target.value)} />
          </label>
          <label className="text-slate-400">type RESTORE_INTO_ISOLATED_ENVIRONMENT
            <input className="ml-2 w-72 rounded bg-slate-900 px-2 py-1 text-slate-200" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </label>
        </div>
      </Card>
      <Card>
        {items.length === 0 && <EmptyState title="No backups recorded" body="Backup runs — including failed ones — are recorded here (§171)." />}
        <div className="divide-y divide-slate-800">
          {items.map((b) => (
            <div key={b.id} className="py-2 text-sm">
              <div className="flex flex-wrap items-center gap-3">
                <Badge>{b.status}</Badge>
                <span className="text-slate-200">{b.kind}</span>
                <span className="text-slate-400">
                  {b.startedAt} · {b.sizeBytes ? `${b.sizeBytes} bytes` : "no artifact"} · {b.durationMs ?? "—"} ms
                  {b.encrypted ? " · encrypted" : ""} · retention until {b.retentionExpiresAt ?? "—"}
                </span>
                <span className="ml-auto flex gap-2">
                  <button className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200" onClick={() => void showRestores(b.id)}>Restore tests</button>
                  <button disabled={busy || b.status !== "COMPLETED"} className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 disabled:opacity-40" onClick={() => void restore(b.id)}>Restore test…</button>
                </span>
              </div>
              {b.errorSummary && <p className="mt-1 text-red-300">{b.errorSummary}</p>}
              {(restores[b.id] ?? []).map((r) => (
                <p key={r.id} className="mt-1 pl-4 text-xs text-slate-400">
                  restore → {r.targetDatabase}: {r.status} · {r.startedAt}{r.errorSummary ? ` · ${r.errorSummary}` : ""}
                </p>
              ))}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
