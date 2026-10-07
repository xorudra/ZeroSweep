"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface RemediationData {
  openCount: number;
  overdue: Record<string, unknown>[];
  dueSoon: Record<string, unknown>[];
  unassigned: Record<string, unknown>[];
  workloadByOwner: Record<string, number>;
  byPriority: Record<string, number>;
  groups: { key: string; kind: string; label: string; findingIds: string[]; openCount: number; worstPriority?: string; hosts: string[] }[];
}

function FindingLinks({ items, empty }: { items: Record<string, unknown>[]; empty: string }) {
  if (items.length === 0) return <p className="mt-1 text-sm text-slate-500">{empty}</p>;
  return (
    <ul className="mt-2 space-y-1 text-sm">
      {items.slice(0, 25).map((f, i) => (
        <li key={i}>
          <Link href={`/vulnerabilities/${String(f.id)}`} className="text-sky-300 hover:underline">{String(f.title)}</Link>
          <span className="text-slate-500"> · {String(f.host ?? "—")} · {String(f.priority ?? "—")} · due {f.dueAt ? new Date(String(f.dueAt)).toLocaleDateString() : "—"}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * Remediation dashboard (Prompt 11 §71): the repair queue, not the
 * detection queue — overdue work first, due-soon next, deterministic
 * root-cause groups (§53/§54), owner workload and unassigned findings.
 * Orchestration/automation of remediation is Prompt 31; this page is
 * the data view.
 */
export default function Page() {
  const [data, setData] = useState<RemediationData | null>(null);
  useEffect(() => {
    apiFetch<RemediationData>("/vulnerabilities/remediation").then(setData).catch(() => setData(null));
  }, []);

  if (!data) return <p className="text-sm text-slate-400">Loading…</p>;
  if (data.openCount === 0) {
    return (
      <>
        <PageHeader eyebrow="Remediation" title="Remediation" />
        <EmptyState title="Nothing to remediate" body="No open vulnerabilities are assigned to the remediation workflow. When findings are triaged and confirmed, the repair queue appears here." />
      </>
    );
  }
  return (
    <>
      <PageHeader eyebrow="Remediation" title="Remediation" body={`${data.openCount} open vulnerabilities in the repair queue. Grouped deterministically by root cause — one fix can close many findings.`} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <h3 className="text-sm font-semibold text-red-300">Overdue SLA ({data.overdue.length})</h3>
          <FindingLinks items={data.overdue} empty="Nothing overdue. " />
        </Card>
        <Card>
          <h3 className="text-sm font-semibold text-amber-300">Due soon ({data.dueSoon.length})</h3>
          <FindingLinks items={data.dueSoon} empty="Nothing in the due-soon window." />
        </Card>
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Unassigned ({data.unassigned.length})</h3>
          <FindingLinks items={data.unassigned} empty="Everything open has an owner." />
        </Card>
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Workload by owner</h3>
          {Object.keys(data.workloadByOwner).length === 0 ? (
            <p className="mt-1 text-sm text-slate-500">No assignments yet.</p>
          ) : (
            <ul className="mt-2 space-y-1 text-sm text-slate-300">
              {Object.entries(data.workloadByOwner).map(([owner, count]) => <li key={owner}>{owner}: {count} open</li>)}
            </ul>
          )}
          <h3 className="mt-4 text-sm font-semibold text-slate-200">By priority</h3>
          <p className="mt-1 text-sm text-slate-300">{Object.entries(data.byPriority).map(([k, v]) => `${k}: ${v}`).join(" · ") || "—"}</p>
        </Card>
      </div>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Remediation groups (§53)</h3>
        <div className="mt-2 overflow-x-auto">
          <table className="w-full min-w-[520px] text-left text-sm">
            <thead className="text-slate-400"><tr><th className="py-2 font-medium">Group</th><th className="font-medium">Kind</th><th className="font-medium">Open</th><th className="font-medium">Worst priority</th><th className="font-medium">Hosts</th></tr></thead>
            <tbody>
              {data.groups.map((g) => (
                <tr key={g.key} className="border-t border-slate-800">
                  <td className="py-2 text-slate-200">{g.label}</td>
                  <td>{g.kind}</td>
                  <td>{g.openCount}</td>
                  <td>{g.worstPriority ? <Badge tone={g.worstPriority}>{g.worstPriority}</Badge> : "—"}</td>
                  <td className="text-slate-400">{g.hosts.slice(0, 4).join(", ")}{g.hosts.length > 4 ? ` +${g.hosts.length - 4}` : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
