"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Mobile application detail (Prompt 17 §94): builds with their
 * SHA-256 identity, build upload through the hostile-content intake
 * (archive attacks + hash mismatch are refused), and gated scan
 * starts. Uploaded artifacts are analyzed STATICALLY in the sandbox
 * — never installed or executed by intake.
 */
interface BuildRow {
  id: string; versionName?: string | null; versionCode?: number | null; artifactHash: string;
  artifactFormat: string; artifactSizeBytes: string; status: string;
  signingSubject?: string | null; findings: number;
}
interface AppData {
  id: string; name: string; platform: string; packageName?: string | null; bundleId?: string | null;
  environment: string; criticality: string; status: string; builds: BuildRow[];
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const PROFILES = ["MOBILE_STATIC_BASELINE", "MOBILE_STATIC_COMPREHENSIVE", "MOBILE_SECRETS_ONLY", "MOBILE_BINARY_ANALYSIS", "MOBILE_DYNAMIC_CONTROLLED", "MOBILE_FULL_CONTROLLED"] as const;

export default function Page() {
  const params = useParams<{ id: string }>();
  const [app, setApp] = useState<AppData | null>(null);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [profile, setProfile] = useState<string>("MOBILE_STATIC_BASELINE");
  const [fileName, setFileName] = useState("");
  const [sha256, setSha256] = useState("");
  const [sizeBytes, setSizeBytes] = useState("");
  const [versionName, setVersionName] = useState("");
  const [entriesJson, setEntriesJson] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<AppData>(`/mobile/apps/${params.id}`);
      setApp(data);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load application");
      setState("error");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const upload = async () => {
    setBusy("upload");
    setNotice("");
    try {
      let archiveEntries: unknown = undefined;
      if (entriesJson.trim()) archiveEntries = JSON.parse(entriesJson) as unknown;
      const res = await apiFetch<{ artifactHash: string; alreadyUploaded?: boolean }>("/mobile/apps/" + params.id + "/builds", {
        method: "POST",
        body: JSON.stringify({
          fileName, versionName: versionName || undefined,
          declaredSha256: sha256 || undefined,
          artifactSizeBytes: Number(sizeBytes) || undefined,
          archiveEntries,
        }),
      });
      setNotice(res.alreadyUploaded
        ? "That exact build (same SHA-256) is already uploaded — builds are identified by hash (§6)."
        : `Build uploaded: ${res.artifactHash.slice(0, 16)}… — intake validated the archive; the artifact is never executed.`);
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : e instanceof SyntaxError ? "Archive entries must be valid JSON" : "Upload failed");
    } finally { setBusy(null); }
  };

  const scan = async () => {
    setBusy("scan");
    setNotice("");
    try {
      const res = await apiFetch<{ scanId: string; status: string }>(`/mobile/apps/${params.id}/scan`, {
        method: "POST",
        body: JSON.stringify({ profile }),
      });
      setNotice(`Scan ${res.scanId} ${res.status.toLowerCase()} with profile ${profile}.`);
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Scan start failed");
    } finally { setBusy(null); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Mobile Security" title={app ? app.name : "Application"} body="Builds, uploads and gated mobile scans." />
      <Link href="/mobile-security" className="text-sm text-indigo-300 hover:underline">← Mobile Security</Link>
      {notice && <p className="text-sm text-amber-300">{notice}</p>}
      {state === "error" && <p className="text-sm text-red-400">{error}</p>}
      {app && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Badge>{app.platform}</Badge>
            <Badge>{app.environment}</Badge>
            <Badge>{app.status}</Badge>
            <span className="text-sm text-slate-400">{app.packageName ?? app.bundleId ?? ""}</span>
          </div>

          <Card>
            <h2 className="mb-3 text-lg font-medium text-slate-100">Upload build</h2>
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-sm text-slate-400">File name
                <input className={`${inputCls} ml-2`} value={fileName} onChange={(e) => setFileName(e.target.value)} placeholder="app-release.apk" />
              </label>
              <label className="text-sm text-slate-400">Version
                <input className={`${inputCls} ml-2 w-24`} value={versionName} onChange={(e) => setVersionName(e.target.value)} placeholder="1.2" />
              </label>
              <label className="text-sm text-slate-400">SHA-256
                <input className={`${inputCls} ml-2 w-64`} value={sha256} onChange={(e) => setSha256(e.target.value)} placeholder="64 hex chars" />
              </label>
              <label className="text-sm text-slate-400">Size (bytes)
                <input className={`${inputCls} ml-2 w-28`} value={sizeBytes} onChange={(e) => setSizeBytes(e.target.value)} placeholder="22000" />
              </label>
              <button disabled={busy !== null || !fileName} onClick={() => void upload()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">
                {busy === "upload" ? "Validating…" : "Upload via intake"}
              </button>
            </div>
            <label className="mt-3 block text-sm text-slate-400">Archive entries (JSON, optional — validated against zip-slip / symlink / zip-bomb rules §107)
              <textarea className={`${inputCls} mt-1 w-full font-mono text-xs`} rows={3} value={entriesJson} onChange={(e) => setEntriesJson(e.target.value)} placeholder='[{"name":"AndroidManifest.xml","uncompressedSize":2048,"compressedSize":900,"isDirectory":false,"isSymlink":false}]' />
            </label>
          </Card>

          <Card>
            <h2 className="mb-3 text-lg font-medium text-slate-100">Start scan</h2>
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-sm text-slate-400">Profile
                <select className={`${inputCls} ml-2`} value={profile} onChange={(e) => setProfile(e.target.value)}>
                  {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </label>
              <button disabled={busy !== null} onClick={() => void scan()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">
                {busy === "scan" ? "Starting…" : "Start scan"}
              </button>
            </div>
            <p className="mt-2 text-xs text-slate-500">Static profiles run on MOBILE_STATIC_ANALYSIS workers; dynamic profiles additionally require an approved lab session and the RUN_MOBILE_DYNAMIC_SCAN permission. The target must be VERIFIED first.</p>
          </Card>

          <Card>
            <h2 className="mb-3 text-lg font-medium text-slate-100">Builds</h2>
            {app.builds.length === 0 && <EmptyState title="No builds yet" body="Upload a build above — it is identified by its SHA-256 (§5/§6)." />}
            <div className="space-y-2">
              {app.builds.map((b) => (
                <div key={b.id} className="flex flex-wrap items-center justify-between gap-2 rounded bg-slate-900 px-3 py-2">
                  <div>
                    <Link href={`/mobile-security/builds/${b.id}`} className="font-medium text-indigo-300 hover:underline">
                      {b.versionName ?? "—"}{b.versionCode ? ` (${b.versionCode})` : ""} · {b.artifactFormat}
                    </Link>
                    <p className="font-mono text-xs text-slate-400">{b.artifactHash.slice(0, 24)}… · {b.artifactSizeBytes} bytes · {b.findings} findings{b.signingSubject ? ` · signed: ${b.signingSubject}` : ""}</p>
                  </div>
                  <Badge>{b.status}</Badge>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
