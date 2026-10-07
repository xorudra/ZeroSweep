"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Image detail (Prompt 13 §85): identity by digest, snapshot/drift
 * history, findings bound to this image, component inventory count and
 * the on-demand CycloneDX SBOM. Static analysis only — the image is
 * never run.
 */
interface ImageDetail {
  id: string; reference: string; registry: string; repository: string;
  tag?: string | null; digest?: string | null; platform?: string | null;
  source: string; componentCount: number;
  snapshots: Array<{ id: string; digest: string; previousDigest?: string | null; drift: boolean; scanId?: string | null; capturedAt?: string }>;
  findings: Array<{ id: string; title: string; severity: string; cve?: string | null; origin?: string | null; controlId?: string | null; status: string }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [image, setImage] = useState<ImageDetail | null>(null);
  const [error, setError] = useState("");
  const [sbomNote, setSbomNote] = useState("");

  const load = useCallback(async () => {
    try {
      setImage(await apiFetch<ImageDetail>(`/container-images/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the image.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  async function downloadSbom() {
    try {
      const sbom = await apiFetch<{ document: unknown; checksum: string; componentCount: number }>(`/container-images/${params.id}/sbom`);
      const blob = new Blob([JSON.stringify(sbom.document, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sbom-${params.id}.cdx.json`;
      a.click();
      URL.revokeObjectURL(url);
      setSbomNote(`SBOM generated: ${sbom.componentCount} components, checksum ${sbom.checksum.slice(0, 12)}…`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "No SBOM inventory yet — run an SBOM profile scan first.");
    }
  }

  if (!image) {
    return <div className="p-6">{error ? <p className="text-sm text-red-300">{error}</p> : <p className="text-sm text-slate-400">Loading…</p>}</div>;
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Container Image" title={image.reference} body="Digest-bound image identity. Findings below were produced by static analysis of this exact image content." />
      <Link className="text-sm text-cyan-300 hover:underline" href="/containers">← All containers</Link>
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {sbomNote && <p className="rounded bg-emerald-950/60 px-3 py-2 text-sm text-emerald-300">{sbomNote}</p>}

      <Card>
        <div className="flex flex-wrap gap-4 text-sm text-slate-300">
          <span>Registry: <span className="font-mono">{image.registry}</span></span>
          <span>Repository: <span className="font-mono">{image.repository}</span></span>
          <span>Tag: {image.tag ?? "—"}</span>
          <span>Digest: <span className="font-mono">{image.digest ?? "not recorded (tag-only)"}</span></span>
          <span>Components: {image.componentCount}</span>
          <Badge>{image.source}</Badge>
          <button className="ml-auto rounded bg-slate-800 px-2 py-1 text-xs text-slate-100" onClick={() => void downloadSbom()}>Download SBOM (CycloneDX)</button>
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Snapshots & drift</h2>
        {image.snapshots.length === 0 && <EmptyState title="No snapshots yet" body="A snapshot is recorded for every scan that resolves this image." />}
        <div className="divide-y divide-slate-800">
          {image.snapshots.map((s) => (
            <div key={s.id} className="flex flex-wrap gap-3 py-2 text-sm">
              <span className="font-mono text-slate-300">{s.digest.slice(0, 19)}…</span>
              {s.drift && <Badge>DRIFT from {s.previousDigest?.slice(0, 19)}…</Badge>}
              <span className="text-slate-500">{s.capturedAt ?? ""}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Findings</h2>
        {image.findings.length === 0 && <EmptyState title="No findings" body="No findings are recorded against this image reference yet." />}
        <div className="divide-y divide-slate-800">
          {image.findings.map((f) => (
            <div key={f.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge>{f.severity}</Badge>
              <span className="text-slate-200">{f.title}</span>
              {f.cve && <span className="font-mono text-slate-400">{f.cve}</span>}
              {f.controlId && <span className="font-mono text-slate-500">{f.controlId}</span>}
              <span className="ml-auto text-slate-500">{f.origin ?? ""} · {f.status}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
