"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, EmptyState } from "@dsrclone/ui";

/**
 * Host detail (Prompt 10 §68/§69): identity, addresses, OS hint WITH
 * confidence (a hint, never a fact), open/closed/filtered ports,
 * services with product/version/CPE/TLS facts and per-service
 * provenance, findings, related endpoints and packet captures.
 * Banners are shown as stored — sanitized at parse time (§36).
 */
interface ServiceRow {
  id: string; port: number; protocol: string; name?: string | null; product?: string | null;
  version?: string | null; state?: string; cpe?: string | null; banner?: string | null;
  tls?: boolean | null; confidence?: number | null; sources?: string[];
}
interface HostDetail {
  id: string; host: string; ip?: string | null; scopeStatus: string;
  osHint?: string | null; osConfidence?: number | null; network?: string | null;
  sources?: string[]; criticality?: string;
  servicesDetail: ServiceRow[];
  technologies: { id: string; name: string; version?: string | null }[];
  findingsDetail: { id: string; title: string; severity: string; vulnClass?: string | null; port?: number | null }[];
  endpoints: { id: string; url: string; method: string; statusCode?: number | null }[];
  packetCaptures: { id: string; format: string; source: string; sizeBytes?: number | null }[];
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [host, setHost] = useState<HostDetail | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    apiFetch<HostDetail>(`/network/hosts/${params.id}`)
      .then((d) => { if (!cancelled) setHost(d); })
      .catch((e: unknown) => { if (!cancelled) setError(e instanceof ApiError ? e.message : "Could not reach the API."); });
    return () => { cancelled = true; };
  }, [params.id]);

  if (error) return <EmptyState title="Host not available" body={error} />;
  if (!host) return <p className="text-sm text-slate-400">Loading…</p>;

  const open = host.servicesDetail.filter((s) => (s.state ?? "OPEN") === "OPEN");

  return (
    <>
      <PageHeader eyebrow="Network · Host" title={host.host} body={`IP ${host.ip ?? "—"} · Network ${host.network ?? "—"} · Sources ${(host.sources ?? []).join(", ") || "—"}`} />
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"><p className="text-2xl font-bold text-slate-50">{open.length}</p><p className="text-xs uppercase tracking-wide text-slate-400">Open ports</p></div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"><p className="text-2xl font-bold text-slate-50">{host.servicesDetail.length}</p><p className="text-xs uppercase tracking-wide text-slate-400">Service records</p></div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"><p className="text-2xl font-bold text-slate-50">{host.findingsDetail.length}</p><p className="text-xs uppercase tracking-wide text-slate-400">Findings</p></div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <p className="text-lg font-bold text-slate-50">{host.osHint ?? "Unknown OS"}</p>
          <p className="text-xs uppercase tracking-wide text-slate-400">OS hint{host.osConfidence ? ` · ${Math.round(host.osConfidence * 100)}% confidence` : ""}</p>
        </div>
      </div>

      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Ports & services</h2>
      {host.servicesDetail.length === 0 && <EmptyState title="No services recorded" body="Service detection has not recorded any port for this host yet." />}
      {host.servicesDetail.length > 0 && (
        <div className="mb-6 overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full min-w-[1000px] text-left text-sm">
            <thead className="bg-slate-900/70 text-slate-400">
              <tr>{["Port", "Protocol", "State", "Service", "Product / Version", "CPE", "TLS", "Confidence", "Sources", "Banner"].map((c) => <th key={c} className="px-4 py-3 font-medium">{c}</th>)}</tr>
            </thead>
            <tbody>
              {host.servicesDetail.map((s) => (
                <tr key={s.id} className="border-t border-slate-800">
                  <td className="px-4 py-3 font-mono text-slate-100">{s.port}</td>
                  <td className="px-4 py-3 text-slate-200">{s.protocol}</td>
                  <td className="px-4 py-3"><Badge>{s.state ?? "OPEN"}</Badge></td>
                  <td className="px-4 py-3 text-slate-200">{s.name ?? "unknown"}</td>
                  <td className="px-4 py-3 text-slate-200">{[s.product, s.version].filter(Boolean).join(" ") || "—"}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">{s.cpe ?? "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{s.tls ? "Yes" : "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{s.confidence !== undefined && s.confidence !== null ? s.confidence.toFixed(2) : "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{(s.sources ?? []).join(", ") || "—"}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">{s.banner ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Findings on this host</h2>
      {host.findingsDetail.length === 0 && <EmptyState title="No findings" body="No governed check has confirmed a condition on this host. Open ports alone are not findings." />}
      {host.findingsDetail.length > 0 && (
        <div className="mb-6 space-y-2">
          {host.findingsDetail.map((f) => (
            <div key={f.id} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="flex items-center justify-between">
                <Link href={`/findings/${f.id}`} className="text-sky-300 hover:underline">{f.title}</Link>
                <Badge>{f.severity}</Badge>
              </div>
              <p className="mt-1 text-xs text-slate-400">{f.vulnClass ?? ""}{f.port ? ` · port ${f.port}` : ""}</p>
            </div>
          ))}
        </div>
      )}

      {host.technologies.length > 0 && (
        <>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Technologies</h2>
          <p className="mb-6 text-sm text-slate-300">{host.technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ""}`).join(", ")}</p>
        </>
      )}
      {host.endpoints.length > 0 && (
        <>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Related endpoints</h2>
          <ul className="mb-6 space-y-1 text-sm text-slate-300">
            {host.endpoints.slice(0, 25).map((e) => <li key={e.id} className="font-mono text-xs">{e.method} {e.url}{e.statusCode ? ` → ${e.statusCode}` : ""}</li>)}
          </ul>
        </>
      )}
      {host.packetCaptures.length > 0 && (
        <>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Packet captures</h2>
          <p className="text-sm text-slate-300">{host.packetCaptures.map((c) => `${c.format} (${c.source})`).join(", ")} — raw access is permission-gated and audited.</p>
        </>
      )}
    </>
  );
}
