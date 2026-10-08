"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Image Detail (Prompt 34 §129): Overview · SBOM · Vulnerabilities ·
 * Secrets · Configuration · Policy · Deployment · Provenance ·
 * History · Verification. Sections render as stacked panels; data
 * comes from the Prompt 13 image record, the Prompt 30 SBOM
 * subsystem and the V2 assessment. Secret findings show metadata
 * only — never a value (§58).
 */
interface ImageDetail {
  id: string; reference: string; registry: string; repository: string;
  tag?: string | null; digest?: string | null;
  snapshots: Array<{ id: string; digest?: string | null; drift: boolean; capturedAt: string }>;
  findings: Array<{ id: string; title: string; severity: string; fingerprint?: string | null; cve?: string | null }>;
}
interface SbomData { componentCount?: number; components?: Array<{ name: string; version?: string | null; purl?: string | null }>; sbom?: { format?: string } | null }
interface AssessData { policy?: { violations: Array<{ rule: string; message: string }> }; deployedIn?: Array<{ namespace: string; kind: string; name: string }>; run?: { status: string } }

const btnCls = "rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50";

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [image, setImage] = useState<ImageDetail | null>(null);
  const [sbom, setSbom] = useState<SbomData | null>(null);
  const [assess, setAssess] = useState<AssessData | null>(null);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [img, sb] = await Promise.all([
        apiFetch<ImageDetail>(`/container-images/${id}`),
        apiFetch<SbomData>(`/container/images/${id}/sbom`).catch(() => null),
      ]);
      setImage(img);
      setSbom(sb);
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load image");
      setState("error");
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  const runAssess = async () => {
    setBusy(true);
    setNotice("");
    try {
      const out = await apiFetch<AssessData>(`/container/images/${id}/assess`, { method: "POST", body: "{}" });
      setAssess(out);
      setNotice(`Assessment ${out.run?.status ?? "done"}`);
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "Assessment failed");
    }
    setBusy(false);
  };

  if (state === "loading") return <div className="p-6 text-slate-400">Loading image…</div>;
  if (state === "error" || !image) return <div className="p-6 text-red-400">{error || "Image not found"}</div>;

  const vulns = image.findings.filter((f) => (f.fingerprint ?? "").startsWith("imgvuln:"));
  const secrets = image.findings.filter((f) => (f.fingerprint ?? "").startsWith("imgsecret:"));
  const configFindings = image.findings.filter((f) => !(f.fingerprint ?? "").startsWith("imgvuln:") && !(f.fingerprint ?? "").startsWith("imgsecret:"));

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Prompt 34" title={image.repository} body={`Image detail (Prompt 34 §129). Identity is the digest — ${image.digest ?? "unresolved (tag-only reference)"}.`} />
      <p className="text-sm text-slate-400"><Link href="/container-security" className="underline">← Container security</Link></p>
      {notice ? <div className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-200">{notice}</div> : null}

      <Card title="Overview">
        <div className="text-sm text-slate-300">
          <p>Reference: {image.reference}</p>
          <p>Registry: {image.registry} · Tag: {image.tag ?? "—"} {image.tag === "latest" ? <Badge>mutable — pin by digest</Badge> : null}</p>
          <p>Digest: <span className="font-mono text-xs">{image.digest ?? "—"}</span></p>
          <button className={btnCls} disabled={busy} onClick={() => void runAssess()}>Run V2 assessment (policy + deployment)</button>
        </div>
      </Card>

      <Card title="SBOM (§52)">
        {sbom ? (
          <div className="text-sm text-slate-300">
            <p>{sbom.componentCount ?? sbom.components?.length ?? 0} component(s){sbom.sbom?.format ? ` · format ${sbom.sbom.format}` : ""}</p>
            <ul className="mt-1 list-disc pl-5">{(sbom.components ?? []).slice(0, 20).map((c, i) => <li key={i}>{c.name} {c.version ?? ""}</li>)}</ul>
          </div>
        ) : <EmptyState title="No SBOM" body="Generate the SBOM from the Containers page (Syft via the governed path)." />}
      </Card>

      <Card title="Vulnerabilities (§56 — Trivy + Grype deduplicated)">
        {vulns.length === 0 ? <EmptyState title="No image vulnerability findings" body="Canonical findings appear here after a governed scan." /> : (
          <ul className="list-disc pl-5 text-sm text-slate-300">{vulns.map((f) => <li key={f.id}>{f.title} <Badge>{f.severity}</Badge> {f.cve ?? ""}</li>)}</ul>
        )}
      </Card>

      <Card title="Secrets (§58 — metadata only, values never shown or stored)">
        {secrets.length === 0 ? <p className="text-sm text-slate-400">No secret findings recorded.</p> : (
          <ul className="list-disc pl-5 text-sm text-slate-300">{secrets.map((f) => <li key={f.id}>{f.title} <Badge>{f.severity}</Badge></li>)}</ul>
        )}
      </Card>

      <Card title="Configuration & policy (§62)">
        {configFindings.length ? <ul className="list-disc pl-5 text-sm text-slate-300">{configFindings.map((f) => <li key={f.id}>{f.title} <Badge>{f.severity}</Badge></li>)}</ul> : null}
        {assess?.policy ? (
          assess.policy.violations.length
            ? <ul className="mt-2 list-disc pl-5 text-sm text-slate-300">{assess.policy.violations.map((v) => <li key={v.rule}>{v.rule}: {v.message}</li>)}</ul>
            : <p className="mt-2 text-sm text-emerald-400">Image satisfies the image policy.</p>
        ) : <p className="mt-2 text-sm text-slate-400">Run the V2 assessment to evaluate the image policy (approved registry, digest pinning, non-root user, vulnerability ceiling).</p>}
      </Card>

      <Card title="Deployment (§87) & provenance (§64)">
        {assess?.deployedIn?.length ? (
          <ul className="list-disc pl-5 text-sm text-slate-300">{assess.deployedIn.map((w, i) => <li key={i}>{w.namespace}/{w.kind}/{w.name} — deployed context raises priority</li>)}</ul>
        ) : <p className="text-sm text-slate-400">Deployment correlation is computed by the V2 assessment. Provenance (source repository, builder, base image, signatures) is recorded as metadata when available — an unsigned image is flagged by policy, never silently trusted.</p>}
      </Card>

      <Card title="History (§63) & verification (§122)">
        {image.snapshots.length === 0 ? <p className="text-sm text-slate-400">No snapshots recorded.</p> : (
          <ul className="list-disc pl-5 text-sm text-slate-300">{image.snapshots.map((s) => <li key={s.id}>{s.capturedAt} — <span className="font-mono text-xs">{(s.digest ?? "").slice(0, 20)}</span> {s.drift ? <Badge>digest changed</Badge> : null}</li>)}</ul>
        )}
        <p className="mt-2 text-sm text-slate-400">Verification requires a new digest + new SBOM + rescan. A tag change alone never verifies a fix.</p>
      </Card>
    </div>
  );
}
