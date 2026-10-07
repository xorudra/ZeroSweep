"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, EmptyState } from "@dsrclone/ui";

interface AdapterRow {
  adapterVersion?: string;
  executionMode?: string;
  supportedTargets?: string[];
  capabilities?: string[];
  enabled?: boolean;
}
interface ToolRow {
  slug: string;
  name: string;
  category: string;
  version?: string | null;
  riskLevel: string;
  healthStatus: string;
  enabled: boolean;
  installed?: boolean;
  licenseType: string;
  adapters?: AdapterRow[];
}

const CATEGORIES = ["RECON", "WEB", "NETWORK", "API", "ACTIVE_DIRECTORY", "PASSWORD_AUDIT", "MOBILE", "CLOUD", "CONTAINER", "SOURCE_CODE", "BINARY", "WIRELESS", "REPORTING"];
const RISKS = ["PASSIVE", "LOW", "MODERATE", "INTRUSIVE", "RESTRICTED"];
const HEALTHS = ["UNKNOWN", "HEALTHY", "DEGRADED", "UNAVAILABLE", "MISCONFIGURED"];

const selectCls = "rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200";

/** Tool Registry (Prompt 3 §43): metadata catalog with search + filters.
 *  There is deliberately NO run/execute control — tools run only through
 *  authorized, approved assessment workflows. */
export default function Page() {
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: ToolRow[] }>({ kind: "loading" });
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [health, setHealth] = useState("");
  const [risk, setRisk] = useState("");
  const [enabled, setEnabled] = useState("");

  useEffect(() => {
    let cancelled = false;
    apiFetch<ToolRow[]>("/tools")
      .then((data) => { if (!cancelled) setState({ kind: "ready", items: Array.isArray(data) ? data : [] }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, []);

  const items = useMemo(() => {
    if (state.kind !== "ready") return [];
    return state.items.filter((t) =>
      (!search || t.name.toLowerCase().includes(search.toLowerCase()) || t.slug.includes(search.toLowerCase()))
      && (!category || t.category === category)
      && (!health || t.healthStatus === health)
      && (!risk || t.riskLevel === risk)
      && (!enabled || (enabled === "enabled") === t.enabled));
  }, [state, search, category, health, risk, enabled]);

  return (
    <>
      <PageHeader eyebrow="Tool Registry" title="Tools" body="Every tool is integrated through a standard adapter with category, risk level, capabilities and health. Tools are never run from this page and there is no command box anywhere in DSRclone — execution happens only through authorized assessment workflows." />
      <div className="mb-4 flex flex-wrap gap-2">
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search tools…" className={`${selectCls} min-w-52`} />
        <select value={category} onChange={(e) => setCategory(e.target.value)} className={selectCls}>
          <option value="">All categories</option>{CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={health} onChange={(e) => setHealth(e.target.value)} className={selectCls}>
          <option value="">All health states</option>{HEALTHS.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <select value={risk} onChange={(e) => setRisk(e.target.value)} className={selectCls}>
          <option value="">All risk levels</option>{RISKS.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <select value={enabled} onChange={(e) => setEnabled(e.target.value)} className={selectCls}>
          <option value="">Enabled + disabled</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option>
        </select>
      </div>
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Nothing to show yet" body={`${state.message} When the API is running and the catalog is seeded, tools appear here — no placeholder data is shown.`} />}
      {state.kind === "ready" && items.length === 0 && <EmptyState title="No tools match" body="No catalog entries match the current filters. Clear a filter or run the database seed to load the full Prompt 3 catalog (metadata only)." />}
      {state.kind === "ready" && items.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="bg-slate-900/70 text-slate-400">
              <tr>{["Tool", "Category", "Version", "Adapter", "Status", "Health", "Risk", "Supported Targets", "Capabilities", "License"].map((c) => <th key={c} className="px-4 py-3 font-medium">{c}</th>)}</tr>
            </thead>
            <tbody>
              {items.map((t) => {
                const a = t.adapters?.[0];
                return (
                  <tr key={t.slug} className="border-t border-slate-800">
                    <td className="px-4 py-3"><Link href={`/tools/${t.slug}`} className="text-sky-300 hover:underline">{t.name}</Link></td>
                    <td className="px-4 py-3 text-slate-300">{t.category}</td>
                    <td className="px-4 py-3 text-slate-300">{t.version ?? "—"}</td>
                    <td className="px-4 py-3 text-slate-300">{a?.adapterVersion ?? "—"}</td>
                    <td className="px-4 py-3 text-slate-300">{t.enabled ? "Enabled" : "Disabled"}</td>
                    <td className="px-4 py-3 text-slate-300">{t.healthStatus}</td>
                    <td className="px-4 py-3"><Badge>{t.riskLevel}</Badge></td>
                    <td className="px-4 py-3 text-slate-300">{(a?.supportedTargets ?? []).join(", ") || "—"}</td>
                    <td className="px-4 py-3 text-slate-300">{(a?.capabilities ?? []).join(", ") || "—"}</td>
                    <td className="px-4 py-3 text-slate-300">{t.licenseType}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
