"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Repository detail (Prompt 12 §91–§95): snapshot + language inventory,
 * code findings with file/line locations, the secret dashboard
 * (metadata only — a secret value is never stored, so it can never be
 * shown), the dependency dashboard with per-component vulnerabilities,
 * the SBOM view, and the latest scan's quality-gate verdict.
 */
interface RepoDetail {
  id: string; name: string; sourceKind: string; remoteUrl?: string | null;
  verified: boolean; findingsBySeverity: { severity: string; count: number }[];
  secrets: number;
  snapshots: Array<{
    id: string; hash: string; commitSha?: string | null; fileCount: number; scanId?: string | null;
    languages?: Array<{ language: string; files: number; share: number }>;
    frameworks?: string[]; buildSystems?: string[]; createdAt?: string;
  }>;
}
interface CodeFinding {
  id: string; title: string; severity: string; status: string; filePath?: string | null;
  startLine?: number | null; ruleId?: string | null; cwe?: string | null; cve?: string | null;
  componentPurl?: string | null; fixedVersion?: string | null; baselineStatus?: string | null;
  sources?: string[];
  secret?: { secretType: string; detector: string; fingerprint: string; redactedPreview?: string | null; lifecycleStatus: string };
}
interface SecretRow {
  id: string; findingId: string; title: string; severity: string; secretType: string; detector: string;
  filePath?: string | null; startLine?: number | null; fingerprint: string; redactedPreview?: string | null;
  verificationStatus: string; lifecycleStatus: string;
}
interface DepRow {
  id: string; name: string; version?: string | null; ecosystem: string; purl: string;
  sourceManifest: string; scope: string; dependencyScope: string; licenses: string[];
  vulnerabilities: Array<{ cve?: string | null; severity: string; fixedVersion?: string | null; reachability?: string | null }>;
}
interface SbomData {
  records: Array<{ id: string; format: string; specVersion: string; checksum: string; componentCount: number }>;
  document: { format: string; specVersion: string; checksum: string; componentCount: number; content: string };
}
interface QualityGate { status: string; policyVersion: string; failedRules: string[]; warningRules: string[]; evaluatedAt?: string }

const LIFECYCLES = ["OPEN", "ROTATION_REQUIRED", "ROTATED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"];
const TABS = ["Overview", "Findings", "Secrets", "Dependencies", "SBOM"] as const;

export default function Page() {
  const params = useParams<{ id: string }>();
  const [repo, setRepo] = useState<RepoDetail | null>(null);
  const [findings, setFindings] = useState<CodeFinding[]>([]);
  const [secrets, setSecrets] = useState<SecretRow[]>([]);
  const [deps, setDeps] = useState<DepRow[]>([]);
  const [sbom, setSbom] = useState<SbomData | null>(null);
  const [gate, setGate] = useState<QualityGate | null>(null);
  const [tab, setTab] = useState<(typeof TABS)[number]>("Overview");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const [r, f, s, d, b] = await Promise.all([
        apiFetch<RepoDetail>(`/repositories/${params.id}`),
        apiFetch<{ items: CodeFinding[] }>(`/repositories/${params.id}/findings?pageSize=100`),
        apiFetch<{ items: SecretRow[] }>(`/repositories/${params.id}/secrets`).catch(() => ({ items: [] as SecretRow[] })),
        apiFetch<{ items: DepRow[] }>(`/repositories/${params.id}/dependencies`),
        apiFetch<SbomData>(`/repositories/${params.id}/sbom`).catch(() => null),
      ]);
      setRepo(r); setFindings(f.items ?? []); setSecrets(s.items ?? []); setDeps(d.items ?? []); setSbom(b);
      const scanId = r.snapshots[0]?.scanId;
      if (scanId) {
        const g = await apiFetch<QualityGate>(`/source-scans/${scanId}/quality-gate`).catch(() => null);
        setGate(g);
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load this repository.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  async function setLifecycle(secretId: string, lifecycleStatus: string) {
    try {
      await apiFetch(`/repositories/${params.id}/secrets/${secretId}`, { method: "PATCH", body: JSON.stringify({ lifecycleStatus }) });
      setNotice(`Secret lifecycle → ${lifecycleStatus}.`);
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Lifecycle update failed.");
    }
  }

  function downloadSbom() {
    if (!sbom) return;
    const isJson = sbom.document.format === "CYCLONEDX_JSON";
    const blob = new Blob([sbom.document.content], { type: isJson ? "application/json" : "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = isJson ? "sbom.cyclonedx.json" : "sbom.spdx";
    a.click();
    URL.revokeObjectURL(url);
  }

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!repo) return <p className="text-sm text-slate-400">Loading…</p>;
  const latest = repo.snapshots[0];

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Repository" title={repo.name} body={`${repo.sourceKind}${repo.remoteUrl ? ` — ${repo.remoteUrl}` : ""} · ${repo.verified ? "Verified target" : "Unverified — scans are refused until verified"}`} />
      {notice ? <p className="text-sm text-cyan-300">{notice}</p> : null}

      <div className="flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`rounded px-3 py-1.5 text-sm ${tab === t ? "bg-cyan-600 text-white" : "bg-slate-800 text-slate-300"}`}>{t}</button>
        ))}
      </div>

      {tab === "Overview" ? (
        <div className="grid gap-4 md:grid-cols-2">
          <Card title="Latest snapshot (§91)">
            {latest ? (
              <dl className="grid grid-cols-2 gap-3 text-sm">
                <dt className="text-slate-500">Hash</dt><dd className="font-mono text-xs text-slate-200">{latest.hash.slice(0, 16)}…</dd>
                <dt className="text-slate-500">Commit</dt><dd className="font-mono text-xs text-slate-200">{latest.commitSha ?? "—"}</dd>
                <dt className="text-slate-500">Files</dt><dd className="text-slate-200">{latest.fileCount}</dd>
                <dt className="text-slate-500">Frameworks</dt><dd className="text-slate-200">{latest.frameworks?.join(", ") || "—"}</dd>
                <dt className="text-slate-500">Build systems</dt><dd className="text-slate-200">{latest.buildSystems?.join(", ") || "—"}</dd>
              </dl>
            ) : <p className="text-sm text-slate-400">No snapshot yet — run a scan to acquire one.</p>}
            {latest?.languages?.length ? (
              <div className="mt-3">
                <p className="text-xs uppercase tracking-wide text-slate-500">Languages (metadata only)</p>
                <ul className="mt-1 text-sm text-slate-300">
                  {latest.languages.map((l) => <li key={l.language}>{l.language} — {l.files} files ({Math.round(l.share * 100)}%)</li>)}
                </ul>
              </div>
            ) : null}
          </Card>
          <Card title="Quality gate — latest scan (§82)">
            {gate ? (
              <div className="space-y-2 text-sm">
                <Badge tone={gate.status === "PASSED" ? "VERIFIED" : gate.status === "WARNING" ? "PENDING" : "CRITICAL"}>{gate.status}</Badge>
                <p className="text-slate-400">Policy {gate.policyVersion}{gate.evaluatedAt ? ` · ${new Date(gate.evaluatedAt).toLocaleString()}` : ""}</p>
                {gate.failedRules.length ? <p className="text-red-300">Failed: {gate.failedRules.join(", ")}</p> : null}
                {gate.warningRules.length ? <p className="text-yellow-200">Warnings: {gate.warningRules.join(", ")}</p> : null}
                <p className="text-xs text-slate-500">The gate verdict is reported alongside the scan status — it never rewrites it.</p>
              </div>
            ) : <p className="text-sm text-slate-400">No quality gate result recorded yet.</p>}
            <div className="mt-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Findings by severity</p>
              <ul className="mt-1 text-sm text-slate-300">
                {repo.findingsBySeverity.map((g) => <li key={g.severity}>{g.severity}: {g.count}</li>)}
              </ul>
            </div>
          </Card>
        </div>
      ) : null}

      {tab === "Findings" ? (
        <Card title="Code findings (§92)">
          {findings.length === 0 ? <EmptyState title="No findings" body="Findings appear after a source scan completes." /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-slate-500"><tr><th className="py-2 pr-3">Severity</th><th className="py-2 pr-3">Finding</th><th className="py-2 pr-3">Location</th><th className="py-2 pr-3">Rule / CWE</th><th className="py-2 pr-3">Baseline</th><th className="py-2">Tools</th></tr></thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.id} className="border-t border-slate-800">
                      <td className="py-2 pr-3"><Badge tone={f.severity}>{f.severity}</Badge></td>
                      <td className="py-2 pr-3"><Link className="text-cyan-300 hover:underline" href={`/findings/${f.id}`}>{f.title}</Link>
                        {f.secret ? <span className="block text-xs text-slate-500">Secret metadata: {f.secret.secretType} · {f.secret.redactedPreview ?? "no preview"} · {f.secret.lifecycleStatus}</span> : null}
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs text-slate-300">{f.filePath ?? f.componentPurl ?? "—"}{f.startLine ? `:${f.startLine}` : ""}</td>
                      <td className="py-2 pr-3 text-xs text-slate-400">{f.ruleId ?? f.cve ?? "—"}{f.cwe ? ` · ${f.cwe}` : ""}</td>
                      <td className="py-2 pr-3 text-slate-300">{f.baselineStatus ?? "—"}</td>
                      <td className="py-2 text-slate-300">{f.sources?.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : null}

      {tab === "Secrets" ? (
        <Card title="Secret dashboard (§93) — metadata only">
          <p className="mb-3 text-xs text-slate-500">Detected secrets are never stored or displayed. Each row carries the type, detector, location, one-way fingerprint and a redacted preview — rotation is driven from this lifecycle, not from the value.</p>
          {secrets.length === 0 ? <EmptyState title="No secret findings" body="No secrets detected, or your role lacks VIEW_SECRET_METADATA." /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-slate-500"><tr><th className="py-2 pr-3">Type</th><th className="py-2 pr-3">Location</th><th className="py-2 pr-3">Preview</th><th className="py-2 pr-3">Verification</th><th className="py-2 pr-3">Lifecycle</th><th className="py-2">Set lifecycle</th></tr></thead>
                <tbody>
                  {secrets.map((s) => (
                    <tr key={s.id} className="border-t border-slate-800">
                      <td className="py-2 pr-3 text-slate-200">{s.secretType}<span className="block text-xs text-slate-500">{s.detector}</span></td>
                      <td className="py-2 pr-3 font-mono text-xs text-slate-300">{s.filePath}{s.startLine ? `:${s.startLine}` : ""}</td>
                      <td className="py-2 pr-3 font-mono text-xs text-slate-300">{s.redactedPreview ?? "—"}</td>
                      <td className="py-2 pr-3 text-slate-300">{s.verificationStatus}</td>
                      <td className="py-2 pr-3"><Badge tone={s.lifecycleStatus === "OPEN" ? "CRITICAL" : "PENDING"}>{s.lifecycleStatus}</Badge></td>
                      <td className="py-2">
                        <select className="rounded bg-slate-900 px-2 py-1 text-xs text-slate-200 border border-slate-700" value={s.lifecycleStatus} onChange={(e) => void setLifecycle(s.id, e.target.value)}>
                          {LIFECYCLES.map((l) => <option key={l} value={l}>{l}</option>)}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : null}

      {tab === "Dependencies" ? (
        <Card title="Dependency dashboard (§94) — latest snapshot">
          {deps.length === 0 ? <EmptyState title="No components inventoried" body="Components appear after the dependency inventory stage runs." /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-slate-500"><tr><th className="py-2 pr-3">Component</th><th className="py-2 pr-3">Ecosystem</th><th className="py-2 pr-3">Scope</th><th className="py-2 pr-3">Licenses</th><th className="py-2">Vulnerabilities</th></tr></thead>
                <tbody>
                  {deps.map((d) => (
                    <tr key={d.id} className="border-t border-slate-800">
                      <td className="py-2 pr-3 text-slate-200">{d.name}{d.version ? `@${d.version}` : ""}<span className="block font-mono text-xs text-slate-500">{d.purl}</span></td>
                      <td className="py-2 pr-3 text-slate-300">{d.ecosystem}</td>
                      <td className="py-2 pr-3 text-slate-300">{d.scope} / {d.dependencyScope}</td>
                      <td className="py-2 pr-3 text-slate-300">{d.licenses.join(", ") || "—"}</td>
                      <td className="py-2 text-slate-300">
                        {d.vulnerabilities.length === 0 ? "—" : d.vulnerabilities.map((v, i) => (
                          <span key={i} className="block text-xs">{v.cve ?? "advisory"} · {v.severity}{v.fixedVersion ? ` · fixed in ${v.fixedVersion}` : ""}{v.reachability ? ` · ${v.reachability}` : ""}</span>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : null}

      {tab === "SBOM" ? (
        <Card title="SBOM (§95)">
          {sbom ? (
            <div className="space-y-3 text-sm">
              <p className="text-slate-300">Generated records: {sbom.records.length}. The document is rebuilt deterministically from the snapshot's component inventory — checksum {sbom.document.checksum.slice(0, 16)}… over {sbom.document.componentCount} components ({sbom.document.format} {sbom.document.specVersion}).</p>
              <button className="rounded bg-cyan-600 px-3 py-1.5 text-sm text-white" onClick={downloadSbom}>Download SBOM</button>
              <pre className="max-h-96 overflow-auto rounded bg-slate-900 p-3 font-mono text-xs text-slate-300">{sbom.document.content.slice(0, 4000)}</pre>
            </div>
          ) : <EmptyState title="No SBOM yet" body="An SBOM is generated by the SBOM stage of a source scan (EXPORT_SBOM permission required to view)." />}
        </Card>
      ) : null}
    </div>
  );
}
