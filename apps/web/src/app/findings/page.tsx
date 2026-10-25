"use client";

import { Suspense, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@zerosweep/ui";

const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
const STATUSES = ["", "OPEN", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"];
const VERIFICATION = ["", "UNVERIFIED", "LIKELY", "CONFIRMED", "REJECTED"];

function fmtDate(v: unknown): string {
  if (typeof v !== "string") return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString();
}

/**
 * Findings dashboard (Prompt 7 §40): canonical findings only (duplicates
 * are merged into them by the correlation stage), filterable by severity /
 * status / verification / tool. Empty means empty — no placeholder
 * vulnerabilities are ever rendered.
 */
function FindingsDashboard() {
  const searchParams = useSearchParams();
  const [scanId] = useState(searchParams.get("scanId") ?? "");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [verification, setVerification] = useState("");
  const [tool, setTool] = useState("");

  const path = useMemo(() => {
    const q = new URLSearchParams();
    if (severity) q.set("severity", severity);
    if (status) q.set("status", status);
    if (verification) q.set("verificationStatus", verification);
    if (tool) q.set("tool", tool);
    if (scanId) q.set("scanId", scanId);
    const qs = q.toString();
    return qs ? `/findings?${qs}` : "/findings";
  }, [severity, status, verification, tool, scanId]);

  const selectCls = "rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200";
  return (
    <>
      <PageHeader
        eyebrow="Findings"
        title="Findings"
        body="Normalized, correlated findings from safe vulnerability detection and TLS assessment. One canonical finding per underlying issue — every contributing tool's evidence is preserved on the detail page."
      />
      <div className="mb-4 flex flex-wrap gap-3">
        <label className="flex items-center gap-2 text-sm text-slate-400">Severity
          <select className={selectCls} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">Status
          <select className={selectCls} value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">Verification
          <select className={selectCls} value={verification} onChange={(e) => setVerification(e.target.value)}>
            {VERIFICATION.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">Tool
          <input className={selectCls} value={tool} onChange={(e) => setTool(e.target.value)} placeholder="nuclei, nikto, testssl…" />
        </label>
      </div>
      <ResourceList
        path={path}
        emptyTitle="No findings yet"
        emptyBody="Findings appear only after real authorized scans run the safe vulnerability detection stage. ZeroSweep never displays placeholder vulnerabilities."
        columns={["Severity", "Finding", "Asset", "Endpoint", "Confidence", "Sources", "Status", "First Seen", "Last Seen"]}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[
            <Badge key="sev" tone={String(item.severity ?? "")}>{String(item.severity ?? "")}</Badge>,
            <Link key="t" href={`/findings/${String(item.id)}`} className="text-sky-300 hover:underline">{String(item.title ?? "")}</Link>,
            String(item.host ?? "—"),
            <span key="ep" className="break-all text-xs text-slate-400">{String(item.endpoint ?? "—")}</span>,
            String(item.confidenceBand ?? (typeof item.confidence === "number" ? item.confidence.toFixed(2) : "—")),
            Array.isArray(item.sources) ? item.sources.join(", ") : "—",
            String(item.status ?? ""),
            fmtDate(item.createdAt),
            fmtDate(item.updatedAt),
          ]} />
        )}
      />
    </>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<p className="text-sm text-slate-400">Loading…</p>}>
      <FindingsDashboard />
    </Suspense>
  );
}
