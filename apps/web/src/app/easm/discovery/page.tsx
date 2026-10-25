"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@zerosweep/ui";

/**
 * EASM programs & discovery (Prompt 29 §101): programs, root assets
 * with their authorization state, discovery policies, and run
 * history with per-source coverage. Live source transports are not
 * wired in this environment — runs without recorded source payloads
 * honestly report NOT_CONFIGURED per source.
 */
interface Program { id: string; name: string; status: string; monitoringEnabled: boolean; monitoringTier: string }
interface Root { id: string; value: string; type: string; authorizationStatus: string; activeTestingStatus: string; verificationChallenge: string }
interface Run { id: string; status: string; trigger: string; finishedAt: string | null; coverage: { configured: number; succeeded: number; skipped: number; failed: number } | null }
interface AdapterResult { adapter: string; status: string; resultCount: number; errorClass: string | null }

export default function Page() {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [selected, setSelected] = useState("");
  const [roots, setRoots] = useState<Root[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [runAdapters, setRunAdapters] = useState<Record<string, AdapterResult[]>>({});
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const loadPrograms = useCallback(async () => {
    try {
      const res = await apiFetch<{ items: Program[] }>("/easm/programs");
      setPrograms(res.items);
      if (res.items[0] && !selected) setSelected(res.items[0].id);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [selected]);

  const loadDetail = useCallback(async () => {
    if (!selected) return;
    try {
      const [r, runRes] = await Promise.all([
        apiFetch<{ items: Root[] }>(`/easm/programs/${selected}/roots`),
        apiFetch<{ items: Run[] }>(`/easm/programs/${selected}/runs`),
      ]);
      setRoots(r.items);
      setRuns(runRes.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load program detail.");
    }
  }, [selected]);

  useEffect(() => { void loadPrograms(); }, [loadPrograms]);
  useEffect(() => { void loadDetail(); }, [loadDetail]);

  const run = async () => {
    try {
      const out = await apiFetch<{ run: Run; adapters: AdapterResult[] }>(`/easm/programs/${selected}/discover`, { method: "POST", body: JSON.stringify({}) });
      setRunAdapters((prev) => ({ ...prev, [out.run.id]: out.adapters }));
      setMessage(`Run ${out.run.status}. Sources succeeded: ${out.run.coverage?.succeeded ?? 0}, skipped: ${out.run.coverage?.skipped ?? 0}, failed: ${out.run.coverage?.failed ?? 0} of ${out.run.coverage?.configured ?? 0}.`);
      await loadDetail();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Discovery failed.");
    }
  };

  return (
    <main>
      <PageHeader eyebrow="EASM" title="EASM Programs & Discovery" />
      <p style={{ color: "var(--muted, #666)", maxWidth: 760 }}>
        Passive discovery is the default. Safe-active sources (DNS resolution, TLS handshake,
        HTTP probe, service discovery) run only for roots that are ownership-VERIFIED and
        separately authorized for active testing, and only on approved ports.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {message ? <p>{message}</p> : null}
      <div style={{ display: "flex", gap: 8 }}>
        <select value={selected} onChange={(e) => setSelected(e.target.value)}>
          {programs.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.status})</option>)}
        </select>
        <button onClick={run} disabled={!selected}>Run discovery</button>
      </div>
      <Card title="Root assets">
        {roots.length === 0 ? <EmptyState title="No root assets yet. Add a seed domain/organization root to start discovery." body="" /> : (
          <table>
            <thead><tr><th>Root</th><th>Type</th><th>Ownership</th><th>Active testing</th><th>Verification challenge</th></tr></thead>
            <tbody>
              {roots.map((r) => (
                <tr key={r.id}>
                  <td>{r.value}</td><td>{r.type}</td><td>{r.authorizationStatus}</td><td>{r.activeTestingStatus}</td>
                  <td><code>{r.verificationChallenge}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p>Publish the challenge as a DNS TXT record (<code>zerosweep-verify=…</code>) and verify from the API — ownership and active testing are separate decisions.</p>
      </Card>
      <Card title="Discovery runs">
        {runs.length === 0 ? <EmptyState title="No discovery runs yet." body="" /> : (
          <ul>
            {runs.map((r) => (
              <li key={r.id}>
                <strong>{r.status}</strong> ({r.trigger}) {r.finishedAt ? new Date(r.finishedAt).toLocaleString() : "running"}
                {(runAdapters[r.id] ?? []).length > 0 ? (
                  <ul>{(runAdapters[r.id] ?? []).map((a, i) => <li key={i}>{a.adapter}: {a.status} ({a.resultCount}){a.errorClass ? ` — ${a.errorClass}` : ""}</li>)}</ul>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </main>
  );
}
