"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/** Framework dashboard (Prompt 26 §77): requirements, mapped controls,
 *  latest assessment result per requirement, assessment history. */
interface FrameworkDashboard {
  framework: { id: string; key: string; name: string; version: string; publisher: string; status: string };
  requirements: Array<{
    id: string; requirementId: string; title: string; level: number;
    mappedControlIds: string[]; latestResult: string;
  }>;
  assessmentHistory: Array<{ id: string; name: string; status: string; frameworkVersion: string; createdAt: string }>;
  disclaimer: string;
}

const RESULT_TONE: Record<string, string> = {
  COMPLIANT: "text-emerald-300", PARTIALLY_COMPLIANT: "text-amber-300",
  NON_COMPLIANT: "text-red-300", NOT_ASSESSED: "text-slate-400", NOT_APPLICABLE: "text-slate-400",
};

export default function Page() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<FrameworkDashboard | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<FrameworkDashboard>(`/grc/dashboard/framework/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="GRC · Framework" title={data ? `${data.framework.name} ${data.framework.version}` : "Framework"} body="Requirement results are assessment states derived from mapped controls and current evidence — not certification claims." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {!data ? (
        <EmptyState title="Loading framework…" body="" />
      ) : (
        <>
          <Card>
            <div className="mb-2 flex items-center gap-2">
              <Badge>{data.framework.status}</Badge>
              <span className="text-sm text-slate-400">Publisher: {data.framework.publisher || "—"} · Key: {data.framework.key}</span>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400">
                  <th className="py-1">Requirement</th><th>Title</th><th>Mapped controls</th><th>Latest result</th>
                </tr>
              </thead>
              <tbody>
                {data.requirements.map((r) => (
                  <tr key={r.id} className="border-t border-slate-800">
                    <td className="py-1 pr-2" style={{ paddingLeft: `${(r.level - 1) * 16}px` }}>{r.requirementId}</td>
                    <td className="pr-2">{r.title}</td>
                    <td className="pr-2">{r.mappedControlIds.length}</td>
                    <td className={RESULT_TONE[r.latestResult] ?? ""}>{r.latestResult}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <Card>
            <h3 className="mb-3 font-medium">Assessment history</h3>
            {data.assessmentHistory.length === 0 ? (
              <EmptyState title="No assessments yet" body="Assessments pin the exact framework version they were created against." />
            ) : (
              <ul className="divide-y divide-slate-800">
                {data.assessmentHistory.map((a) => (
                  <li key={a.id} className="flex items-center justify-between py-2 text-sm">
                    <span>{a.name} <span className="text-slate-400">· framework {a.frameworkVersion}</span></span>
                    <Badge>{a.status}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
