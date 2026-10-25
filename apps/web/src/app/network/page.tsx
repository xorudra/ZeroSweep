"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, EmptyState } from "@zerosweep/ui";

/**
 * Network VAPT dashboard (Prompt 10 §66/§67/§70/§72). Networks, hosts,
 * open ports, services, technologies and findings from authorized
 * network scans. Open ports are INVENTORY — a port becomes a finding
 * only when a governed safe check confirmed a condition. The network
 * map is drawn ONLY from recorded relationships (hosts belonging to a
 * network, known IPs) — nothing is guessed (§70).
 */
interface NetworkGroup { network: string; hosts: number; openPorts: number; services: number; findings: number }
interface HostRow {
  id: string; host: string; ip?: string | null; scopeStatus: string;
  osHint?: string | null; osConfidence?: number | null; network?: string | null;
  openPorts: number; services: number; findings: number; endpoints: number;
  sources?: string[]; lastSeen?: string;
}
interface CaptureRow { id: string; format: string; source: string; sizeBytes?: number | null; createdAt?: string; scanId?: string | null }
interface NetworkTool { slug: string; name: string; healthStatus: string; capabilities: string[]; riskLevel: string; requiredWorkerType?: string | null; manual?: boolean }

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [networks, setNetworks] = useState<NetworkGroup[]>([]);
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [captures, setCaptures] = useState<CaptureRow[]>([]);
  const [tools, setTools] = useState<NetworkTool[]>([]);
  const [search, setSearch] = useState("");
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const params = new URLSearchParams({ pageSize: "100" });
        if (search) params.set("search", search);
        const [n, h, c, t] = await Promise.all([
          apiFetch<{ networks: NetworkGroup[] }>("/network/networks"),
          apiFetch<{ items: HostRow[] }>(`/network/hosts?${params.toString()}`),
          apiFetch<{ captures: CaptureRow[] }>("/network/packet-captures"),
          apiFetch<{ tools: NetworkTool[] }>("/network/tools"),
        ]);
        if (cancelled) return;
        setNetworks(n.networks ?? []);
        setHosts(h.items ?? []);
        setCaptures(c.captures ?? []);
        setTools(t.tools ?? []);
        setState("ready");
      } catch (e) {
        if (!cancelled) { setError(e instanceof ApiError ? e.message : "Could not reach the API."); setState("error"); }
      }
    })();
    return () => { cancelled = true; };
  }, [search]);

  const totals = networks.reduce((acc, n) => ({
    hosts: acc.hosts + n.hosts, openPorts: acc.openPorts + n.openPorts,
    services: acc.services + n.services, findings: acc.findings + n.findings,
  }), { hosts: 0, openPorts: 0, services: 0, findings: 0 });

  return (
    <>
      <PageHeader eyebrow="Network VAPT" title="Network" body="Hosts, ports and services discovered by authorized network scans (Nmap / Naabu / RustScan and governed safe checks). Open ports are inventory; findings exist only where a governed check confirmed a condition." />
      {state === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state === "error" && <EmptyState title="Nothing to show yet" body={`${error} When the API is running and network scans have run, hosts and services will appear here.`} />}
      {state === "ready" && (
        <>
          <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-5">
            {[
              ["Networks", networks.length], ["Hosts discovered", totals.hosts],
              ["Open ports", totals.openPorts], ["Services identified", totals.services],
              ["Findings", totals.findings],
            ].map(([label, value]) => (
              <div key={label as string} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                <p className="text-2xl font-bold text-slate-50">{value as number}</p>
                <p className="text-xs uppercase tracking-wide text-slate-400">{label as string}</p>
              </div>
            ))}
          </div>

          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Network map — recorded relationships only</h2>
          {networks.length === 0 && <EmptyState title="No networks yet" body="Run a network profile (NETWORK_DISCOVERY / NETWORK_BASELINE / NETWORK_COMPREHENSIVE / NETWORK_INTERNAL) against a verified CIDR or IP target." />}
          <div className="mb-6 grid gap-3 md:grid-cols-2">
            {networks.map((n) => (
              <div key={n.network} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                <p className="font-mono text-sm text-cyan-300">{n.network}</p>
                <p className="mt-1 text-sm text-slate-300">{n.hosts} host(s) · {n.openPorts} open port(s) · {n.services} service record(s) · {n.findings} finding(s)</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {hosts.filter((h) => (h.network ?? "UNGROUPED") === n.network).slice(0, 12).map((h) => (
                    <Link key={h.id} href={`/network/hosts/${h.id}`} className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-200 hover:bg-slate-700">{h.host}</Link>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-300">Hosts</h2>
            <input aria-label="Search hosts" className={inputCls} placeholder="Search hosts" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          {hosts.length === 0 && <EmptyState title="No hosts yet" body="Hosts appear after a network scan discovers them inside an approved scope." />}
          {hosts.length > 0 && (
            <div className="mb-6 overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full min-w-[900px] text-left text-sm">
                <thead className="bg-slate-900/70 text-slate-400">
                  <tr>{["Host", "IP", "Network", "Scope", "OS hint", "Open ports", "Findings", "Sources", "Last seen"].map((c) => <th key={c} className="px-4 py-3 font-medium">{c}</th>)}</tr>
                </thead>
                <tbody>
                  {hosts.map((h) => (
                    <tr key={h.id} className="border-t border-slate-800">
                      <td className="px-4 py-3"><Link href={`/network/hosts/${h.id}`} className="font-mono text-sky-300 hover:underline">{h.host}</Link></td>
                      <td className="px-4 py-3 text-slate-200">{h.ip ?? "—"}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">{h.network ?? "—"}</td>
                      <td className="px-4 py-3"><Badge>{h.scopeStatus}</Badge></td>
                      <td className="px-4 py-3 text-slate-200">{h.osHint ? `${h.osHint}${h.osConfidence ? ` (${Math.round(h.osConfidence * 100)}%)` : ""}` : "—"}</td>
                      <td className="px-4 py-3 text-slate-200">{h.openPorts}</td>
                      <td className="px-4 py-3 text-slate-200">{h.findings}</td>
                      <td className="px-4 py-3 text-slate-200">{(h.sources ?? []).join(", ") || "—"}</td>
                      <td className="px-4 py-3 text-slate-400">{h.lastSeen ? new Date(h.lastSeen).toLocaleDateString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Network tools</h2>
          <div className="mb-6 grid gap-3 md:grid-cols-3">
            {tools.map((t) => (
              <div key={t.slug} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                <div className="flex items-center justify-between">
                  <p className="font-medium text-slate-100">{t.name}</p>
                  <Badge>{t.healthStatus}</Badge>
                </div>
                <p className="mt-1 text-xs text-slate-400">Risk: {t.riskLevel}{t.requiredWorkerType ? ` · Worker: ${t.requiredWorkerType}` : ""}{t.manual ? " · Manual tool" : ""}</p>
                <p className="mt-1 text-xs text-slate-500">{t.capabilities.join(", ")}</p>
              </div>
            ))}
          </div>

          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Packet captures</h2>
          {captures.length === 0 && <EmptyState title="No captures" body="Authorized captures (imports or bounded tcpdump runs on packet-analysis workers) appear here as metadata. Raw access is permission-gated and audited." />}
          {captures.length > 0 && (
            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full min-w-[700px] text-left text-sm">
                <thead className="bg-slate-900/70 text-slate-400">
                  <tr>{["Format", "Source", "Size", "Scan", "Captured"].map((c) => <th key={c} className="px-4 py-3 font-medium">{c}</th>)}</tr>
                </thead>
                <tbody>
                  {captures.map((c) => (
                    <tr key={c.id} className="border-t border-slate-800">
                      <td className="px-4 py-3 text-slate-200">{c.format}</td>
                      <td className="px-4 py-3 text-slate-200">{c.source}</td>
                      <td className="px-4 py-3 text-slate-200">{c.sizeBytes ? `${c.sizeBytes} B` : "—"}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">{c.scanId ?? "—"}</td>
                      <td className="px-4 py-3 text-slate-400">{c.createdAt ? new Date(c.createdAt).toLocaleString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </>
  );
}
