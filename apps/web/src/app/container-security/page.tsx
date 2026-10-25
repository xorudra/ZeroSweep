"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@zerosweep/ui";

/**
 * Container Security dashboard (Prompt 34 §3/§128). Image identity is
 * the DIGEST (§49): the same digest under two tags is one image.
 * Scans and SBOMs run through the governed Prompt 13/30 paths; this
 * page adds image-policy evaluation (§62), the Container Orchestrator
 * (§104), coverage (§113) and baselines (§99). Images are analyzed,
 * never executed.
 */
interface ImageRow {
  id: string; reference: string; registry: string; repository: string;
  tag?: string | null; digest?: string | null; identity: string; componentCount: number;
  latestSnapshot?: { config?: { user?: string } } | null;
}
interface CoverageRow { id: string; completion: string; imagesCovered: number; sbomCoverage: number | null; gaps: Array<{ area: string; reason: string }> }
interface BaselineRow { id: string; version: number; hash: string }
interface Deviation { ruleId: string; message: string }

const btnCls = "rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50";

export default function Page() {
  const [images, setImages] = useState<ImageRow[]>([]);
  const [coverage, setCoverage] = useState<CoverageRow[]>([]);
  const [baselines, setBaselines] = useState<BaselineRow[]>([]);
  const [deviations, setDeviations] = useState<Deviation[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [img, cov, base] = await Promise.all([
        apiFetch<{ items: ImageRow[] }>("/container/images"),
        apiFetch<{ items: CoverageRow[] }>("/container/coverage"),
        apiFetch<{ items: BaselineRow[] }>("/container/baselines"),
      ]);
      setImages(img.items ?? []);
      setCoverage(cov.items ?? []);
      setBaselines(base.items ?? []);
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load container security");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<string>) => {
    setBusy(key);
    setNotice("");
    try { setNotice(await fn()); } catch (err) { setNotice(err instanceof ApiError ? err.message : "Action failed"); }
    setBusy(null);
  };

  const assess = (id: string) => act(`assess-${id}`, async () => {
    const out = await apiFetch<{ run: { status: string }; policy: { violations: Array<{ rule: string }> } }>(`/container/images/${id}/assess`, { method: "POST", body: "{}" });
    const cov = await apiFetch<{ items: CoverageRow[] }>("/container/coverage");
    setCoverage(cov.items ?? []);
    return `Assessment ${out.run.status}; policy violations: ${out.policy.violations.map((v) => v.rule).join(", ") || "none"}`;
  });

  const scan = (id: string) => act(`scan-${id}`, async () => {
    const out = await apiFetch<{ id: string }>(`/container/images/${id}/scan`, { method: "POST", body: "{}" });
    return `Governed scan queued via the Prompt 13 path: ${out.id}`;
  });

  const createBaseline = () => act("baseline", async () => {
    const b = await apiFetch<BaselineRow>("/container/baselines", { method: "POST", body: "{}" });
    const base = await apiFetch<{ items: BaselineRow[] }>("/container/baselines");
    setBaselines(base.items ?? []);
    return `Container baseline v${b.version} created`;
  });

  const checkDrift = () => act("drift", async () => {
    const out = await apiFetch<{ deviations: Deviation[] }>("/container/baseline-drift");
    setDeviations(out.deviations ?? []);
    return `${(out.deviations ?? []).length} deviation(s)`;
  });

  if (state === "loading") return <div className="p-6 text-slate-400">Loading container security…</div>;
  if (state === "error") return <div className="p-6 text-red-400">{error}</div>;

  const latest = coverage[0];

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Prompt 34" title="Container Security" body="Images, SBOM coverage, image policy, deployment correlation and baselines (Prompt 34 §128). Identity = digest; images are analyzed, never run." />
      {notice ? <div className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-200">{notice}</div> : null}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Images" value={images.length} />
        <StatCard label="With SBOM" value={images.filter((i) => i.componentCount > 0).length} />
        <StatCard label="Baselines" value={baselines.length} />
        <StatCard label="Latest completion" value={latest?.completion ?? "—"} />
      </div>

      <Card title="Images (§48/§49)">
        {images.length === 0 ? <EmptyState title="No images registered" body="Register images on the Containers page; identity is pinned by digest here." /> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Image</th><th>Digest identity</th><th>Tag</th><th>SBOM components</th><th>Actions</th></tr></thead>
            <tbody>
              {images.map((img) => (
                <tr key={img.id} className="border-t border-slate-800">
                  <td className="py-2"><Link href={`/container-security/images/${img.id}`} className="underline">{img.repository}</Link><div className="text-xs text-slate-500">{img.registry}</div></td>
                  <td className="font-mono text-xs">{img.identity.slice(0, 24)}…</td>
                  <td>{img.tag === "latest" ? <Badge>latest — mutable</Badge> : img.tag ?? "—"}</td>
                  <td>{img.componentCount}</td>
                  <td className="space-x-2">
                    <button className={btnCls} disabled={busy !== null} onClick={() => void scan(img.id)}>Scan</button>
                    <button className={btnCls} disabled={busy !== null} onClick={() => void assess(img.id)}>Assess</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Coverage (§113)">
        {latest ? (
          <div className="text-sm">
            <p>Images covered: {latest.imagesCovered} · SBOM coverage: {latest.sbomCoverage === null ? "unknown (nothing observed)" : `${Math.round(latest.sbomCoverage * 100)}%`} · Completion: <Badge>{latest.completion}</Badge></p>
            <ul className="mt-2 list-disc pl-5 text-slate-300">{latest.gaps.map((g, i) => <li key={i}>{g.area} — {g.reason}</li>)}</ul>
          </div>
        ) : <EmptyState title="No coverage yet" body="Run an image assessment to compute coverage." />}
      </Card>

      <Card title="Container Security Baseline (§99) & drift (§100)">
        <div className="flex gap-2">
          <button className={btnCls} disabled={busy !== null} onClick={() => void createBaseline()}>Create baseline version</button>
          <button className={btnCls} disabled={busy !== null || baselines.length === 0} onClick={() => void checkDrift()}>Check drift</button>
        </div>
        <p className="mt-2 text-sm text-slate-400">{baselines.map((b) => `v${b.version} (${b.hash.slice(0, 8)}…)`).join(" · ") || "No baselines yet."}</p>
        {deviations.length ? <ul className="mt-2 list-disc pl-5 text-sm text-slate-300">{deviations.map((d) => <li key={d.ruleId}>{d.ruleId}: {d.message}</li>)}</ul> : null}
      </Card>

      <Card title="Verification (§122)">
        <p className="text-sm text-slate-300">A fix is VERIFIED only by a new digest, a new SBOM and a rescan — a tag change alone never verifies anything. SBOM truth lives on the Prompt 30 subsystem; this page never duplicates it.</p>
      </Card>
    </div>
  );
}
