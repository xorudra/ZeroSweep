"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

const LIFECYCLES = ["", "NEW", "TRIAGED", "CONFIRMED", "IN_PROGRESS", "REMEDIATED", "RETEST_PENDING", "RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"];
const PRIORITIES = ["", "P0", "P1", "P2", "P3", "P4"];
const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
const SORTS = ["risk", "epss", "sla", "newest", "oldest", "recurring"];

interface Dashboard {
  totalOpen: number; criticalPriority: number; highSeverity: number; kevFindings: number;
  internetFacing: number; overdueSla: number; newThisPeriod: number; resolvedThisPeriod: number;
  meanTimeToRemediateHours: number | null; retestSuccessRate: number | null;
  definitions: Record<string, string>;
}

function fmtDate(v: unknown): string {
  if (typeof v !== "string") return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString();
}

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <Card>
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-slate-100">{value}</div>
      {hint ? <div className="mt-1 text-xs text-slate-500">{hint}</div> : null}
    </Card>
  );
}

/**
 * Vulnerability Management dashboard (Prompt 11 §65/§66): metrics are
 * computed by the API from canonical finding rows only (duplicates are
 * observations, never double-counted). Zero-data states render as
 * honest zeros / "—", never as invented numbers.
 */
function VulnerabilitiesPage() {
  const [dash, setDash] = useState<Dashboard | null>(null);
  const [lifecycle, setLifecycle] = useState("");
  const [priority, setPriority] = useState("");
  const [severity, setSeverity] = useState("");
  const [kev, setKev] = useState("");
  const [sort, setSort] = useState("risk");
  const [search, setSearch] = useState("");

  useEffect(() => {
    apiFetch<Dashboard>("/vulnerabilities/dashboard").then(setDash).catch(() => setDash(null));
  }, []);

  const path = useMemo(() => {
    const q = new URLSearchParams();
    if (lifecycle) q.set("lifecycleStatus", lifecycle);
    if (priority) q.set("priority", priority);
    if (severity) q.set("severity", severity);
    if (kev) q.set("kev", kev);
    if (search) q.set("search", search);
    q.set("sort", sort);
    return `/vulnerabilities?${q.toString()}`;
  }, [lifecycle, priority, severity, kev, sort, search]);

  const selectCls = "rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200";
  return (
    <>
      <PageHeader
        eyebrow="Vulnerability Management"
        title="Vulnerabilities"
        body="The management layer over evidence-backed findings: lifecycle, ownership, SLA, intelligence (CVE / EPSS / KEV from the governed local dataset only) and retests. Intelligence badges appear only when local data actually supports them."
      />
      {dash ? (
        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Total Open" value={dash.totalOpen} />
          <Stat label="Critical Priority (P0/P1)" value={dash.criticalPriority} hint="priority ≠ severity" />
          <Stat label="High Severity" value={dash.highSeverity} />
          <Stat label="KEV Listed" value={dash.kevFindings} hint="CISA Known Exploited Vulnerabilities" />
          <Stat label="Internet-Facing" value={dash.internetFacing} hint="tagged internet-facing" />
          <Stat label="Overdue SLA" value={dash.overdueSla} />
          <Stat label="New / Resolved (30d)" value={`${dash.newThisPeriod} / ${dash.resolvedThisPeriod}`} />
          <Stat label="MTTR / Retest Success" value={dash.meanTimeToRemediateHours === null ? "—" : `${Math.round(dash.meanTimeToRemediateHours)}h`} hint={dash.retestSuccessRate === null ? "no completed retests yet" : `retest success ${(dash.retestSuccessRate * 100).toFixed(0)}%`} />
        </div>
      ) : (
        <p className="mb-6 text-sm text-slate-500">Dashboard metrics load from the API; with no findings they are honest zeros.</p>
      )}
      <div className="mb-4 flex flex-wrap gap-3">
        <label className="flex items-center gap-2 text-sm text-slate-400">Lifecycle
          <select className={selectCls} value={lifecycle} onChange={(e) => setLifecycle(e.target.value)}>
            {LIFECYCLES.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">Priority
          <select className={selectCls} value={priority} onChange={(e) => setPriority(e.target.value)}>
            {PRIORITIES.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">Severity
          <select className={selectCls} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">KEV
          <select className={selectCls} value={kev} onChange={(e) => setKev(e.target.value)}>
            <option value="">All</option>
            <option value="true">KEV listed</option>
            <option value="false">Not KEV listed</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">Sort
          <select className={selectCls} value={sort} onChange={(e) => setSort(e.target.value)}>
            {SORTS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">Search
          <input className={selectCls} value={search} onChange={(e) => setSearch(e.target.value)} placeholder="title contains…" />
        </label>
        <Link href="/remediation" className="ml-auto self-center text-sm text-sky-300 hover:underline">Remediation dashboard →</Link>
      </div>
      <ResourceList
        path={path}
        emptyTitle="No vulnerabilities yet"
        emptyBody="Vulnerabilities appear after authorized scans detect them (or governed scanner reports are imported). DSRclone never displays placeholder vulnerabilities."
        columns={["Priority", "Severity", "Vulnerability", "Asset", "CVE", "EPSS", "KEV", "Status", "Owner", "SLA", "First Seen", "Last Seen"]}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[
            item.priority ? <Badge key="p" tone={String(item.priority)}>{String(item.priority)}</Badge> : "—",
            <Badge key="sev" tone={String(item.severity ?? "")}>{String(item.severity ?? "")}</Badge>,
            <Link key="t" href={`/vulnerabilities/${String(item.id)}`} className="text-sky-300 hover:underline">{String(item.title ?? "")}</Link>,
            String(item.host ?? "—"),
            item.cve ? <Link key="cve" href={`/vulnerabilities/cve/${String(item.cve)}`} className="text-sky-300 hover:underline">{String(item.cve)}</Link> : "—",
            typeof item.epssScore === "number" ? item.epssScore.toFixed(3) : "—",
            item.kevListed ? <Badge key="kev" tone="CRITICAL">KEV</Badge> : "—",
            String(item.lifecycleStatus ?? ""),
            String(item.assignedToId ?? item.assignedToTeam ?? "—"),
            String(item.slaStatus ?? ""),
            fmtDate(item.firstSeen),
            fmtDate(item.lastSeen),
          ]} />
        )}
      />
    </>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<p className="text-sm text-slate-400">Loading…</p>}>
      <VulnerabilitiesPage />
    </Suspense>
  );
}
