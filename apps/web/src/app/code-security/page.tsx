"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Code Security dashboard (Prompt 12 §89/§90). Repositories are
 * first-class targets; their content is treated as hostile input and is
 * NEVER executed — analysis runs read-only over immutable snapshots.
 * Secrets appear as metadata only (type, detector, fingerprint,
 * redacted preview) — no secret value exists anywhere in the platform.
 */
interface RepoRow {
  id: string; name: string; sourceKind: string; provider?: string | null;
  remoteUrl?: string | null; defaultBranch?: string | null; visibility: string;
  verified: boolean; credentialReference?: string | null;
  snapshots: number; findings: number; secrets: number;
  latestSnapshot?: { id: string; hash: string; createdAt?: string } | null;
  createdAt?: string;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const SOURCE_PROFILES = ["SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SECRETS_ONLY", "DEPENDENCIES_ONLY", "SAST_ONLY"] as const;

export default function Page() {
  const [repos, setRepos] = useState<RepoRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [profile, setProfile] = useState<string>("SOURCE_BASELINE");
  // Create form
  const [name, setName] = useState("");
  const [sourceKind, setSourceKind] = useState("LOCAL_SOURCE_SNAPSHOT");
  const [remoteUrl, setRemoteUrl] = useState("");
  const [manifestJson, setManifestJson] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: RepoRow[] }>("/repositories");
      setRepos(data.items ?? []);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function createRepo() {
    setBusy("create"); setNotice("");
    try {
      const body: Record<string, unknown> = { name, sourceKind };
      if (sourceKind === "GIT_REMOTE") {
        body.remoteUrl = remoteUrl;
      } else {
        body.snapshotManifest = JSON.parse(manifestJson || "{}");
      }
      await apiFetch("/repositories", { method: "POST", body: JSON.stringify(body) });
      setNotice("Repository registered. Verify it, then start a scan.");
      setName(""); setRemoteUrl(""); setManifestJson("");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Registration failed — check the manifest JSON and URL guards.");
    } finally { setBusy(null); }
  }

  async function verify(id: string) {
    setBusy(id); setNotice("");
    try {
      await apiFetch(`/repositories/${id}/verify`, { method: "POST", body: "{}" });
      setNotice("Repository verified.");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Verification failed.");
    } finally { setBusy(null); }
  }

  async function startScan(id: string) {
    setBusy(id); setNotice("");
    try {
      const res = await apiFetch<{ scanId: string }>(`/repositories/${id}/scans`, { method: "POST", body: JSON.stringify({ profile }) });
      setNotice(`Scan ${res.scanId} queued with profile ${profile}. Watch progress under Scans.`);
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Scan start refused — the repository must be verified first.");
    } finally { setBusy(null); }
  }

  const totals = {
    repos: repos.length,
    snapshots: repos.reduce((s, r) => s + r.snapshots, 0),
    findings: repos.reduce((s, r) => s + r.findings, 0),
    secrets: repos.reduce((s, r) => s + r.secrets, 0),
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Source Code Security" title="Code Security" body="SAST, secrets and dependency analysis over immutable repository snapshots. Source code is analyzed read-only and never executed; secrets are stored as fingerprints and redacted previews only." />
      {state === "error" ? <p className="text-sm text-red-400">{error}</p> : null}
      {notice ? <p className="text-sm text-cyan-300">{notice}</p> : null}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {[
          ["Repositories", totals.repos],
          ["Snapshots", totals.snapshots],
          ["Code findings", totals.findings],
          ["Secret findings (metadata)", totals.secrets],
        ].map(([label, value]) => (
          <Card key={label as string} title={label as string}>
            <p className="text-3xl font-bold text-slate-50">{value as number}</p>
          </Card>
        ))}
      </div>

      <Card title="Register a repository (§89)">
        <div className="grid gap-3 md:grid-cols-2">
          <label className="text-sm text-slate-400">Name
            <input className={`${inputCls} mt-1 w-full`} value={name} onChange={(e) => setName(e.target.value)} placeholder="fixture-repo" />
          </label>
          <label className="text-sm text-slate-400">Source kind
            <select className={`${inputCls} mt-1 w-full`} value={sourceKind} onChange={(e) => setSourceKind(e.target.value)}>
              <option value="LOCAL_SOURCE_SNAPSHOT">Local source snapshot</option>
              <option value="UPLOADED_ARCHIVE">Uploaded archive</option>
              <option value="GIT_REMOTE">Git remote (URL intake, SSRF-guarded)</option>
              <option value="MANUAL_IMPORT">Manual import</option>
            </select>
          </label>
          {sourceKind === "GIT_REMOTE" ? (
            <label className="text-sm text-slate-400 md:col-span-2">Remote URL (https/ssh; credentials only as reference names — never in the URL)
              <input className={`${inputCls} mt-1 w-full`} value={remoteUrl} onChange={(e) => setRemoteUrl(e.target.value)} placeholder="https://github.com/example/project.git" />
            </label>
          ) : (
            <label className="text-sm text-slate-400 md:col-span-2">Snapshot manifest JSON — file listing + manifest contents (data only, never executed)
              <textarea className={`${inputCls} mt-1 w-full font-mono text-xs`} rows={6} value={manifestJson} onChange={(e) => setManifestJson(e.target.value)} placeholder='{"files":[{"path":"src/app.py","sizeBytes":120}],"manifests":{"requirements.txt":"flask==1.1.2\n"}}' />
            </label>
          )}
        </div>
        <button className="mt-3 rounded bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50" disabled={busy === "create" || !name} onClick={() => void createRepo()}>
          Register repository
        </button>
      </Card>

      <Card title="Repositories (§90)">
        {state === "loading" ? <p className="text-sm text-slate-400">Loading…</p> : repos.length === 0 ? (
          <EmptyState title="No repositories registered" body="Register a repository snapshot or an SSRF-guarded git remote to begin source analysis." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr><th className="py-2 pr-3">Repository</th><th className="py-2 pr-3">Kind</th><th className="py-2 pr-3">Verified</th><th className="py-2 pr-3">Latest snapshot</th><th className="py-2 pr-3">Findings</th><th className="py-2 pr-3">Secrets</th><th className="py-2">Actions</th></tr>
              </thead>
              <tbody>
                {repos.map((r) => (
                  <tr key={r.id} className="border-t border-slate-800">
                    <td className="py-2 pr-3">
                      <Link className="text-cyan-300 hover:underline" href={`/code-security/repositories/${r.id}`}>{r.name}</Link>
                      {r.remoteUrl ? <span className="block max-w-xs truncate text-xs text-slate-500">{r.remoteUrl}</span> : null}
                    </td>
                    <td className="py-2 pr-3 text-slate-300">{r.sourceKind}</td>
                    <td className="py-2 pr-3">{r.verified ? <Badge tone="VERIFIED">VERIFIED</Badge> : <Badge tone="PENDING">UNVERIFIED</Badge>}</td>
                    <td className="py-2 pr-3 font-mono text-xs text-slate-400">{r.latestSnapshot ? r.latestSnapshot.hash.slice(0, 12) : "—"}</td>
                    <td className="py-2 pr-3 text-slate-200">{r.findings}</td>
                    <td className="py-2 pr-3 text-slate-200">{r.secrets}</td>
                    <td className="py-2">
                      <div className="flex flex-wrap items-center gap-2">
                        {!r.verified ? (
                          <button className="rounded bg-slate-700 px-2 py-1 text-xs text-slate-100 disabled:opacity-50" disabled={busy === r.id} onClick={() => void verify(r.id)}>Verify</button>
                        ) : null}
                        <select className={`${inputCls} text-xs`} value={profile} onChange={(e) => setProfile(e.target.value)}>
                          {SOURCE_PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
                        </select>
                        <button className="rounded bg-cyan-600 px-2 py-1 text-xs text-white disabled:opacity-50" disabled={busy === r.id || !r.verified} onClick={() => void startScan(r.id)}>Start scan</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
