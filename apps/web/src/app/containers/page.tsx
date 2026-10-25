"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Container security (Prompt 13 §84). Images are inventoried by digest
 * and analyzed STATICALLY — layers and config only. Nothing on this
 * page (or anywhere in ZeroSweep) runs an image. Registry credentials
 * are secret-reference names only.
 */
interface ImageRow {
  id: string; reference: string; registry: string; repository: string;
  tag?: string | null; digest?: string | null; source: string;
  findings: number; lastSeen?: string;
}
interface RegistryRow {
  id: string; name: string; url: string; provider?: string | null;
  credentialReference?: string | null;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const PROFILES = ["CONTAINER_BASELINE", "CONTAINER_COMPREHENSIVE", "SBOM_ONLY", "IMAGE_VULNERABILITIES_ONLY", "CONTAINER_MISCONFIG_ONLY"] as const;

export default function Page() {
  const [images, setImages] = useState<ImageRow[]>([]);
  const [registries, setRegistries] = useState<RegistryRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [profile, setProfile] = useState<string>("CONTAINER_BASELINE");
  const [reference, setReference] = useState("");
  const [regName, setRegName] = useState("");
  const [regUrl, setRegUrl] = useState("");
  const [regCred, setRegCred] = useState("");

  const load = useCallback(async () => {
    try {
      const [img, reg] = await Promise.all([
        apiFetch<{ items: ImageRow[] }>("/container-images"),
        apiFetch<{ items: RegistryRow[] }>("/container-registries"),
      ]);
      setImages(img.items ?? []);
      setRegistries(reg.items ?? []);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function registerImage() {
    setBusy("image");
    try {
      await apiFetch("/container-images", { method: "POST", body: JSON.stringify({ image: reference }) });
      setReference("");
      setNotice("Image registered. Verify its target registration, then start a scan.");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Registration failed.");
    } finally { setBusy(null); }
  }

  async function createRegistry() {
    setBusy("registry");
    try {
      await apiFetch("/container-registries", {
        method: "POST",
        body: JSON.stringify({ name: regName, url: regUrl, ...(regCred ? { credentialReference: regCred } : {}) }),
      });
      setRegName(""); setRegUrl(""); setRegCred("");
      setNotice("Registry connection saved (credential stored as a reference name only).");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Registry save failed.");
    } finally { setBusy(null); }
  }

  async function scan(id: string) {
    setBusy(id);
    try {
      const out = await apiFetch<{ scanId?: string }>(`/container-images/${id}/scan`, { method: "POST", body: JSON.stringify({ profile }) });
      setNotice(`Scan started (${out.scanId ?? "queued"}) with profile ${profile}. Follow progress under Scans.`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Scan start failed — the image target must be VERIFIED first.");
    } finally { setBusy(null); }
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Container Security" title="Containers" body="Static image analysis by digest — layers and configuration are inspected, images are never executed. Secrets surface as metadata only." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {notice && <p className="rounded bg-emerald-950/60 px-3 py-2 text-sm text-emerald-300">{notice}</p>}

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Register image</h2>
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-xs text-slate-400">Reference (tag and/or digest)
            <input className={`${inputCls} w-96`} placeholder="registry.example.com/team/webapp:1.4.2" value={reference} onChange={(e) => setReference(e.target.value)} />
          </label>
          <button className="rounded bg-cyan-700 px-3 py-1.5 text-sm text-white disabled:opacity-50" disabled={busy === "image" || !reference} onClick={() => void registerImage()}>Register</button>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Scan profile
            <select className={inputCls} value={profile} onChange={(e) => setProfile(e.target.value)}>
              {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
        </div>
        <p className="mt-2 text-xs text-slate-500">Example: Rudra registers <span className="font-mono">registry.example.com/team/webapp:1.4.2</span> — the digest recorded at scan time is the identity that findings bind to; a changed digest is drift, never an overwrite.</p>
      </Card>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Images</h2>
        {state === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
        {state === "ready" && images.length === 0 && <EmptyState title="No images registered" body="Register an image reference above to start static analysis." />}
        <div className="divide-y divide-slate-800">
          {images.map((img) => (
            <div key={img.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Link className="font-mono text-cyan-300 hover:underline" href={`/containers/${img.id}`}>{img.reference}</Link>
              <Badge>{img.source}</Badge>
              <span className="text-slate-400">{img.digest ? `digest ${img.digest.slice(0, 19)}…` : "tag-only (no digest recorded)"}</span>
              <span className="text-slate-400">{img.findings} findings</span>
              <button className="ml-auto rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 disabled:opacity-50" disabled={busy === img.id} onClick={() => void scan(img.id)}>Scan ({profile})</button>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Registries</h2>
        <div className="mb-3 flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-xs text-slate-400">Name
            <input className={inputCls} placeholder="production" value={regName} onChange={(e) => setRegName(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">URL (https, SSRF-checked)
            <input className={`${inputCls} w-72`} placeholder="https://registry.example.com" value={regUrl} onChange={(e) => setRegUrl(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Credential reference (name only)
            <input className={inputCls} placeholder="prod-registry-creds" value={regCred} onChange={(e) => setRegCred(e.target.value)} />
          </label>
          <button className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-100 disabled:opacity-50" disabled={busy === "registry" || !regName || !regUrl} onClick={() => void createRegistry()}>Save registry</button>
        </div>
        <div className="divide-y divide-slate-800">
          {registries.map((r) => (
            <div key={r.id} className="flex flex-wrap gap-3 py-2 text-sm">
              <span className="text-slate-100">{r.name}</span>
              <span className="font-mono text-slate-400">{r.url}</span>
              <span className="text-slate-500">{r.credentialReference ? `credential: ${r.credentialReference} (reference)` : "no credential reference"}</span>
            </div>
          ))}
          {registries.length === 0 && <p className="py-2 text-sm text-slate-500">No registries registered.</p>}
        </div>
      </Card>
    </div>
  );
}
